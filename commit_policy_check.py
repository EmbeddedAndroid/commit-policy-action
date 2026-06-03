#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# Review the commits of a pull request against an OpenEmbedded / Yocto layer
# contribution policy (the style documented in a repo's AGENTS.md), and post
# the result back to the pull request as a review.
#
# The rule engine is pure, deterministic and configurable so it can be unit
# tested with real commit fixtures (see tests/test_commit_policy.py) and
# reused across repositories that follow the same review pattern. Three thin
# adapters wrap it: a local-git loader (for development), a GitHub API loader
# (for CI, needs no checkout of the reviewed repo), and a review poster.
#
# Only rules that can be decided from the commit text and the diff are
# implemented. Semantic judgements (does the body explain why, does the
# subject truthfully describe the diff, are unrelated changes bundled) are
# deliberately left to human review; this tool never claims to replace it.

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_UPSTREAM_STATUS = (
    "accepted", "pending", "inappropriate", "backport",
    "submitted", "denied", "inactive-upstream",
)


@dataclass
class Config:
    """Per-repository tuning. Defaults suit meta-qcom-style layers."""
    # Component prefixes that collide with a Conventional Commits type but are
    # legitimate here (e.g. meta-qcom's "ci: base.lock: ...").
    cc_allow_components: frozenset = frozenset({"ci"})
    subject_max_length: int = 80
    valid_upstream_status: frozenset = frozenset(DEFAULT_UPSTREAM_STATUS)
    disable_rules: frozenset = frozenset()
    patch_check: bool = True
    guidelines: str = "AGENTS.md"


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class PatchFile:
    """A .patch/.diff file added or modified by the pull request."""
    path: str
    content: str
    status: str = "A"  # A=added, M=modified, R=renamed, D=deleted


@dataclass
class Commit:
    """A single commit in the pull request range (base..head)."""
    sha: str = ""
    author_name: str = ""
    author_email: str = ""
    committer_name: str = ""
    committer_email: str = ""
    message: str = ""
    parents: list = field(default_factory=list)

    @property
    def short_sha(self):
        return self.sha[:12] if self.sha else "(working)"

    @property
    def subject(self):
        return self.message.splitlines()[0] if self.message.strip() else ""

    @property
    def body_lines(self):
        return self.message.splitlines()[1:]


@dataclass
class Finding:
    """A single policy violation attributed to a commit or a patch file."""
    rule: str
    severity: str  # "error" or "warning"
    message: str
    commit: str = ""
    subject: str = ""
    path: str = ""
    line: int = 0  # 1-based line for an inline review comment


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

# A well-formed Signed-off-by trailer: name, mandatory space, then an address
# in angle brackets. The space before "<" rejects "Name<addr>" trailers.
SIGNOFF_RE = re.compile(
    r"^Signed-off-by:\s*(?P<name>.*\S)\s+<(?P<email>[^<>\s]+@[^<>\s]+)>\s*$"
)
SIGNOFF_PREFIX_RE = re.compile(r"^Signed-off-by:", re.IGNORECASE)

NOREPLY_RE = re.compile(r"@users\.noreply\.github\.com$", re.IGNORECASE)
WEBCLIENT_LOCAL_RE = re.compile(r"^\d+\+")  # e.g. 82081381+wayi-art@...

# Conventional Commits subject prefixes, which OE layers do not use. The
# parenthesised "type(scope):" form is always conventional (optionally with
# whitespace before the scope). The bare "type:" form is matched against the
# closed Conventional Commits vocabulary; a type in cc_allow_components is
# treated as a legitimate component instead.
CC_SCOPE_RE = re.compile(r"^[A-Za-z][\w-]*\s*\([^)]*\)\s*!?\s*:")
CC_TYPE_RE = re.compile(
    r"^(feat|fix|chore|refactor|perf|style|docs|build|test|revert|ci)\s*!?\s*:",
    re.IGNORECASE)

# Kernel-tree subject prefixes, which OE layers do not use. Case-insensitive
# and tolerant of whitespace before the colon so "Fromlist:" / "UPSTREAM :"
# cannot slip past.
KERNEL_PREFIX_RE = re.compile(
    r"^(FROMLIST|FROMGIT|UPSTREAM|BACKPORT)\s*:", re.IGNORECASE)

# A component prefix whose colon is not followed by a space. The negative
# lookahead for "/" avoids flagging a leading URL.
COLON_SPACE_RE = re.compile(r"^[\w][\w.+/-]*:(?!/)\S")

# Leftover work-in-progress / fixup commits that must be squashed.
FIXUP_RE = re.compile(r"^(fixup!|squash!|amend!)\s")
WIP_RE = re.compile(r"^\[?wip\]?\b", re.IGNORECASE)

# GitHub web-editor commit subjects: a verb plus a single filename-like token.
WEBEDIT_VERB_RE = re.compile(r"^(Update|Create|Delete) (\S+)$")
UPLOAD_RE = re.compile(r"^(Add|Update|Delete|Create) files via upload$")
# Well-known extensionless filenames the web editor produces.
WEBEDIT_KNOWN_FILES = frozenset({
    "kconfig", "kbuild", "dockerfile", "containerfile", "makefile", "rakefile",
    "gemfile", "vagrantfile", "readme", "license", "copying", "maintainers",
    "notice", "authors", "changelog", "todo",
})

UPSTREAM_STATUS_RE = re.compile(
    r"^Upstream-Status:[ \t]*([A-Za-z-]+)", re.IGNORECASE | re.MULTILINE)

# Trailers asserting a person's involvement. Any such trailer for an identity
# other than the author or committer cannot be verified deterministically and
# is surfaced for a human. No end-of-line anchor, so a trailing comment after
# the address (e.g. "Acked-by: X <e> # note") cannot hide the trailer.
IDENTITY_TRAILER_RE = re.compile(
    r"^(Signed-off-by|Co-developed-by|Co-authored-by|Reviewed-by|Acked-by"
    r"|Tested-by|Reported-by|Suggested-by):"
    r"\s*(.+?)\s+<([^<>\s]+@[^<>\s]+)>",
    re.IGNORECASE | re.MULTILINE)


def parse_signoffs(message):
    """Return (well_formed, malformed) Signed-off-by trailers."""
    well_formed, malformed = [], []
    for line in message.splitlines():
        if not SIGNOFF_PREFIX_RE.match(line):
            continue
        m = SIGNOFF_RE.match(line)
        if m:
            well_formed.append((m.group("name").strip(), m.group("email").strip()))
        else:
            malformed.append(line.strip())
    return well_formed, malformed


def is_webedit_subject(subject):
    """True for an auto-generated GitHub web-editor commit subject."""
    if UPLOAD_RE.match(subject):
        return True
    m = WEBEDIT_VERB_RE.match(subject)
    if not m:
        return False
    token = m.group(2)
    if "." in token or "/" in token:
        return True
    return token.lower() in WEBEDIT_KNOWN_FILES


def body_is_empty(commit):
    """True when the commit has no real body (only blank lines / trailers)."""
    trailer = re.compile(r"^[A-Za-z][A-Za-z-]+:\s")
    for line in commit.body_lines:
        stripped = line.strip()
        if not stripped or trailer.match(stripped):
            continue
        return False
    return True


# --------------------------------------------------------------------------
# Rule engine
# --------------------------------------------------------------------------

def check_commit(commit, cfg=None):
    """Return the list of Findings for a single commit."""
    cfg = cfg or Config()
    out = []

    def add(rule, severity, message):
        out.append(Finding(rule=rule, severity=severity, message=message,
                           commit=commit.short_sha, subject=commit.subject))

    subject = commit.subject

    # --- subject structure -------------------------------------------------
    if not subject.strip():
        add("subject-empty", "error", "Commit has an empty subject line.")
    else:
        cc_type = CC_TYPE_RE.match(subject)
        cc_is_allowed = bool(cc_type) and (
            cc_type.group(1).lower() in cfg.cc_allow_components)
        if KERNEL_PREFIX_RE.match(subject):
            prefix = re.split(r"\s*:", subject, 1)[0]
            add("kernel-prefix", "error",
                f"Drop the kernel-tree prefix '{prefix}:'; use a "
                f"'component: summary' subject.")
        elif CC_SCOPE_RE.match(subject) or (cc_type and not cc_is_allowed):
            add("conventional-commit", "error",
                "Drop the Conventional Commits prefix; use a "
                "'component: imperative summary' subject.")
        elif COLON_SPACE_RE.match(subject):
            add("component-colon-space", "error",
                "Add a space after the colon ('component: summary').")

        if FIXUP_RE.match(subject) or WIP_RE.match(subject):
            add("fixup-commit", "error",
                "Work-in-progress/fixup commit; squash it into the commit "
                "it belongs to.")
        elif is_webedit_subject(subject):
            add("webedit-subject", "error",
                "GitHub web-editor subject; write a 'component: summary' "
                "line and squash the series.")

        if len(subject) > cfg.subject_max_length:
            add("subject-too-long", "warning",
                f"Subject is {len(subject)} characters; keep it short "
                f"(aim for ~50).")

    # --- merge commits -----------------------------------------------------
    if len(commit.parents) >= 2:
        add("merge-commit", "error",
            "Merge commit in the series; rebase your branch on the target "
            "branch instead of merging it in.")

    # --- Signed-off-by / identity -----------------------------------------
    signoffs, malformed = parse_signoffs(commit.message)

    for _ in malformed:
        add("signoff-malformed", "error",
            "Malformed Signed-off-by trailer; use 'Signed-off-by: Name "
            "<email>' with a space before '<'.")

    if not signoffs and not malformed:
        add("signoff-missing", "error",
            "Missing Signed-off-by trailer; commit with 'git commit -s'.")

    sob_emails = {e.lower() for _, e in signoffs}
    sob_names = {n.lower() for n, _ in signoffs}
    if signoffs:
        if commit.author_email and commit.author_email.lower() not in sob_emails:
            add("signoff-author-mismatch", "error",
                f"Author '{commit.author_email}' has no matching "
                f"Signed-off-by trailer.")
        elif commit.author_name and commit.author_name.lower() not in sob_names:
            add("signoff-name-mismatch", "warning",
                f"Author name '{commit.author_name}' does not match the "
                f"Signed-off-by name.")

    identities = [("author", commit.author_email)]
    identities += [("signoff", e) for _, e in signoffs]
    flagged_webclient = flagged_noreply = False
    for kind, email in identities:
        if not email or not NOREPLY_RE.search(email):
            continue
        local = email.split("@", 1)[0]
        if WEBCLIENT_LOCAL_RE.match(local) and not flagged_webclient:
            flagged_webclient = True
            add("identity-webclient", "error",
                f"{kind} '{email}' is a GitHub web-editor noreply identity; "
                f"re-author with a real name and email.")
        elif not WEBCLIENT_LOCAL_RE.match(local) and not flagged_noreply:
            flagged_noreply = True
            add("identity-noreply", "warning",
                f"{kind} '{email}' is a GitHub noreply address; prefer a "
                f"routable email.")

    # --- unverifiable co-trailers -----------------------------------------
    own = {e.lower() for e in (commit.author_email, commit.committer_email) if e}
    others = [f"{tt} {nm} <{em}>"
              for tt, nm, em in IDENTITY_TRAILER_RE.findall(commit.message)
              if em.lower() not in own]
    if others:
        add("unverified-cotrailer", "warning",
            "Trailers for someone other than the author or committer must be "
            "confirmed by a maintainer: " + "; ".join(others) + ".")

    # --- body --------------------------------------------------------------
    if subject.strip() and body_is_empty(commit):
        add("body-empty", "warning",
            "Commit has no body; non-trivial changes should explain why.")

    return out


def check_patch_files(patch_files, cfg=None):
    """Return Findings for patch files added/modified by the pull request."""
    cfg = cfg or Config()
    out = []
    for pf in patch_files:
        if pf.status == "D":
            continue
        m = UPSTREAM_STATUS_RE.search(pf.content)
        if not m:
            out.append(Finding(
                rule="patch-upstream-status", severity="error",
                message=("Missing 'Upstream-Status:' header "
                         "(Submitted/Backport/Pending/Inappropriate/Denied)."),
                path=pf.path, line=1))
        elif m.group(1).lower() not in cfg.valid_upstream_status:
            out.append(Finding(
                rule="patch-upstream-status", severity="error",
                message=(f"Invalid Upstream-Status value '{m.group(1)}'; use "
                         f"Submitted/Backport/Pending/Inappropriate/Denied."),
                path=pf.path, line=1))
    return out


def check_all(commits, patch_files=None, cfg=None):
    """Run every enabled rule and return the full list of Findings."""
    cfg = cfg or Config()
    findings = []
    for c in commits:
        findings.extend(check_commit(c, cfg))
    if patch_files and cfg.patch_check:
        findings.extend(check_patch_files(patch_files, cfg))
    if cfg.disable_rules:
        findings = [f for f in findings if f.rule not in cfg.disable_rules]
    return findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def has_errors(findings):
    return any(f.severity == "error" for f in findings)


def _plural(n):
    return "" if n == 1 else "s"


def render_text(findings):
    """Human-readable report for local use and CI logs."""
    if not findings:
        return "Commit policy: no issues found.\n"
    lines, by_commit, file_level = [], {}, []
    for f in findings:
        if f.path:
            file_level.append(f)
        else:
            by_commit.setdefault((f.commit, f.subject), []).append(f)
    for (sha, subject), fs in by_commit.items():
        lines.append(f"commit {sha} {subject}")
        for f in fs:
            mark = "ERROR" if f.severity == "error" else "warn "
            lines.append(f"  [{mark}] {f.rule}: {f.message}")
        lines.append("")
    if file_level:
        lines.append("patch files:")
        for f in file_level:
            mark = "ERROR" if f.severity == "error" else "warn "
            lines.append(f"  [{mark}] {f.path}: {f.message}")
        lines.append("")
    errs = sum(1 for f in findings if f.severity == "error")
    warns = sum(1 for f in findings if f.severity == "warning")
    lines.append(f"{errs} error(s), {warns} warning(s).")
    return "\n".join(lines) + "\n"


def render_review_body(findings, guidelines="AGENTS.md"):
    """Plain-text review body: neat, accurate, no decorative markup."""
    if not findings:
        return (f"Commit policy check passed. No issues found. "
                f"See {guidelines} for the commit guidelines.")

    errs = sum(1 for f in findings if f.severity == "error")
    warns = sum(1 for f in findings if f.severity == "warning")
    parts = [f"Commit policy check found {errs} blocking issue{_plural(errs)} "
             f"and {warns} warning{_plural(warns)}. "
             f"See {guidelines} for the commit guidelines."]

    by_commit, file_level = {}, []
    for f in findings:
        if f.path:
            file_level.append(f)
        else:
            by_commit.setdefault((f.commit, f.subject), []).append(f)

    for (sha, subject), fs in by_commit.items():
        parts += ["", f"Commit {sha} ({subject}):", ""]
        for f in fs:
            parts.append(f"- {f.severity}, {f.rule}: {f.message}")
    if file_level:
        parts += ["", "Patch files:", ""]
        for f in file_level:
            parts.append(f"- {f.severity}, {f.path}: {f.message}")
    return "\n".join(parts)


def build_review(findings, approve_on_pass=False, guidelines="AGENTS.md"):
    """Return a (payload-without-commit_id) dict for the PR reviews API."""
    inline = [
        {"path": f.path, "line": f.line, "side": "RIGHT", "body": f.message}
        for f in findings if f.path and f.line
    ]
    body = render_review_body(findings, guidelines)
    if has_errors(findings):
        event = "REQUEST_CHANGES"
    elif findings:
        event = "COMMENT"
    else:
        event = "APPROVE" if approve_on_pass else "COMMENT"
    payload = {"event": event, "body": body}
    if inline:
        payload["comments"] = inline
    return payload


# --------------------------------------------------------------------------
# git adapter (local development)
# --------------------------------------------------------------------------

def _git(args, cwd):
    return subprocess.run(["git"] + args, cwd=cwd, check=True,
                          capture_output=True, text=True).stdout


_SEP = "\x1e"
_FMT = "%H%x1e%P%x1e%an%x1e%ae%x1e%cn%x1e%ce%x1e%B%x00"


def load_commits_git(base, head, cwd="."):
    out = _git(["log", f"{base}..{head}", f"--format={_FMT}"], cwd)
    commits = []
    for rec in out.split("\x00"):
        rec = rec.strip("\n")
        if not rec.strip():
            continue
        sha, parents, an, ae, cn, ce, msg = rec.split(_SEP, 6)
        commits.append(Commit(
            sha=sha, parents=parents.split() if parents.strip() else [],
            author_name=an, author_email=ae,
            committer_name=cn, committer_email=ce, message=msg))
    commits.reverse()
    return commits


def load_patch_files_git(base, head, cwd="."):
    out = _git(["diff", "--name-status", f"{base}..{head}"], cwd)
    patch_files = []
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        status, path = cols[0][0], cols[-1]
        if not path.endswith((".patch", ".diff")) or status == "D":
            continue
        try:
            content = _git(["show", f"{head}:{path}"], cwd)
        except subprocess.CalledProcessError:
            continue
        patch_files.append(PatchFile(path=path, content=content, status=status))
    return patch_files


# --------------------------------------------------------------------------
# GitHub API adapter (CI; needs no checkout of the reviewed repo)
# --------------------------------------------------------------------------

_API = "https://api.github.com"


def _api(method, url, token, data=None, accept="application/vnd.github+json"):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", accept)
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as resp:
        payload = resp.read()
        if accept.endswith("raw"):
            return resp.status, payload.decode("utf-8", "replace"), resp.headers
        return resp.status, json.loads(payload or b"null"), resp.headers


def _next_link(link_header):
    for part in (link_header or "").split(","):
        seg = part.split(";")
        if len(seg) >= 2 and 'rel="next"' in seg[1]:
            return seg[0].strip().strip("<>")
    return None


def _get_all(url, token):
    items = []
    while url:
        _, data, headers = _api("GET", url, token)
        items.extend(data)
        url = _next_link(headers.get("Link"))
    return items


def load_commits_api(repo, pr, token):
    data = _get_all(f"{_API}/repos/{repo}/pulls/{pr}/commits?per_page=100", token)
    commits = []
    for c in data:
        ca = c["commit"].get("author") or {}
        cc = c["commit"].get("committer") or {}
        commits.append(Commit(
            sha=c["sha"], parents=[p["sha"] for p in c.get("parents", [])],
            author_name=ca.get("name", ""), author_email=ca.get("email", ""),
            committer_name=cc.get("name", ""), committer_email=cc.get("email", ""),
            message=c["commit"]["message"]))
    return commits


def load_patch_files_api(repo, pr, head_sha, token):
    files = _get_all(f"{_API}/repos/{repo}/pulls/{pr}/files?per_page=100", token)
    out = []
    for f in files:
        path = f["filename"]
        if not path.endswith((".patch", ".diff")) or f["status"] == "removed":
            continue
        url = (f"{_API}/repos/{repo}/contents/"
               f"{urllib.parse.quote(path)}?ref={head_sha}")
        try:
            _, content, _ = _api("GET", url, token,
                                 accept="application/vnd.github.raw")
        except urllib.error.HTTPError:
            continue
        out.append(PatchFile(path=path, content=content,
                             status=f["status"][0].upper()))
    return out


def post_review(repo, pr, head_sha, payload, token):
    """Submit the review, degrading gracefully when GitHub rejects it."""
    url = f"{_API}/repos/{repo}/pulls/{pr}/reviews"
    body = dict(payload)
    if head_sha:
        body["commit_id"] = head_sha

    attempts = [body]
    if "comments" in body:
        attempts.append({k: v for k, v in body.items() if k != "comments"})
    if body.get("event") == "REQUEST_CHANGES":
        attempts.append({**{k: v for k, v in body.items() if k != "comments"},
                         "event": "COMMENT"})

    last_err = None
    for attempt in attempts:
        try:
            status, _, _ = _api("POST", url, token, attempt)
            return status, attempt["event"]
        except urllib.error.HTTPError as e:
            last_err = f"{e.code} {e.read().decode(errors='replace')[:300]}"
    raise RuntimeError(f"could not post review: {last_err}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _str2bool(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _csv(v):
    return frozenset(s.strip().lower() for s in (v or "").split(",") if s.strip())


def _config_from_args(args):
    cfg = Config()
    if args.cc_allow_components is not None:
        cfg.cc_allow_components = _csv(args.cc_allow_components)
    if args.subject_max_length is not None:
        cfg.subject_max_length = int(args.subject_max_length)
    if args.valid_upstream_status:
        cfg.valid_upstream_status = _csv(args.valid_upstream_status)
    if args.disable_rules:
        cfg.disable_rules = _csv(args.disable_rules)
    cfg.patch_check = args.patch_check
    cfg.guidelines = args.guidelines
    return cfg


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    src = p.add_argument_group("source (choose git range or --api)")
    src.add_argument("--base", help="base ref/sha (excluded) for git mode")
    src.add_argument("--head", help="head ref/sha for git mode")
    src.add_argument("--repo-dir", default=".", help="git checkout directory")
    src.add_argument("--api", action="store_true",
                     help="load the PR via the GitHub API (no checkout)")
    src.add_argument("--repo", help="owner/name (api / review)")
    src.add_argument("--pr", help="pull request number (api / review)")
    src.add_argument("--head-sha", help="PR head sha (api / review commit_id)")

    cf = p.add_argument_group("policy configuration")
    cf.add_argument("--cc-allow-components",
                    help="comma list of component prefixes to allow despite "
                         "matching a Conventional Commits type (default: ci)")
    cf.add_argument("--subject-max-length", help="soft subject length warning")
    cf.add_argument("--valid-upstream-status",
                    help="comma list of accepted Upstream-Status values")
    cf.add_argument("--disable-rules", help="comma list of rule ids to skip")
    cf.add_argument("--guidelines", default="AGENTS.md",
                    help="doc name cited in the review body")
    cf.add_argument("--patch-check", type=_str2bool, default=True,
                    help="check Upstream-Status on patch files (true/false)")

    out = p.add_argument_group("output / review")
    out.add_argument("--format", choices=["text", "json"], default="text")
    out.add_argument("--post-review", type=_str2bool, default=False,
                     help="post the result to the PR (needs --repo/--pr/token)")
    out.add_argument("--approve-on-pass", type=_str2bool, default=False)
    out.add_argument("--fail-on-error", type=_str2bool, default=True,
                     help="exit non-zero when a blocking issue is found")
    args = p.parse_args(argv)

    cfg = _config_from_args(args)

    if args.api:
        if not (args.repo and args.pr):
            p.error("--api needs --repo and --pr")
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            p.error("--api needs $GITHUB_TOKEN")
        commits = load_commits_api(args.repo, args.pr, token)
        head_sha = args.head_sha or (commits[-1].sha if commits else "")
        patch_files = (load_patch_files_api(args.repo, args.pr, head_sha, token)
                       if cfg.patch_check else [])
    else:
        if not (args.base and args.head):
            p.error("git mode needs --base and --head (or use --api)")
        commits = load_commits_git(args.base, args.head, args.repo_dir)
        patch_files = (load_patch_files_git(args.base, args.head, args.repo_dir)
                       if cfg.patch_check else [])
        head_sha = args.head_sha or (commits[-1].sha if commits else "")

    findings = check_all(commits, patch_files, cfg)

    if args.format == "json":
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        sys.stderr.write(f"Checked {len(commits)} commit(s) and "
                         f"{len(patch_files)} patch file(s).\n")
        sys.stdout.write(render_text(findings))

    if args.post_review:
        token = os.environ.get("GITHUB_TOKEN", "")
        if not (args.repo and args.pr and token):
            sys.stderr.write("--post-review needs --repo, --pr and "
                             "$GITHUB_TOKEN\n")
            return 2
        payload = build_review(findings, args.approve_on_pass, cfg.guidelines)
        status, event = post_review(args.repo, args.pr, head_sha, payload, token)
        sys.stderr.write(f"Posted {event} review (HTTP {status}).\n")

    return 1 if (args.fail_on_error and has_errors(findings)) else 0


if __name__ == "__main__":
    sys.exit(main())
