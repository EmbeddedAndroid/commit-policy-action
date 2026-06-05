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
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    # GitHub-verified accounts the author/committer emails map to. Populated
    # in API mode (empty in git mode); "" means "no account / unknown".
    author_login: str = ""
    committer_login: str = ""

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

# Kernel-tree subject prefixes, which OE layers do not use. A small closed
# vocabulary, like the Conventional Commits types: these look like valid
# components but are not, so they cannot be decided by shape alone. Open-ended
# case/whitespace variants are folded away by normalize_subject() first.
KERNEL_PREFIX_RE = re.compile(
    r"^(FROMLIST|FROMGIT|UPSTREAM|BACKPORT)\s*:", re.IGNORECASE)

# A "prefix attempt": a non-space, non-colon run immediately followed by a
# colon at the start of the subject. A bare imperative whose summary merely
# contains a colon (e.g. 'Revert "foo: bar"') has no such leading token.
PREFIX_ATTEMPT_RE = re.compile(r"^[^\s:]+:")
# The single canonical good shape: a lowercase component, colon, then a space.
# A prefix attempt that does not match this (capitalised, missing space, stray
# punctuation) is caught by one positive check instead of many blacklists.
COMPONENT_CANONICAL_RE = re.compile(r"^[a-z0-9][\w.+/-]*: \S")

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

# A cherry-pick / backport marker (git cherry-pick -x). On such a commit the
# author is legitimately not the PR submitter, so identity is not flagged.
CHERRY_PICK_RE = re.compile(r"cherry[\s-]*picked from commit", re.IGNORECASE)

# Trailers asserting a person's involvement. Matched by shape - any
# "Word-by:" trailer (Signed-off-by, Acked-by, Reviewed-by, Approved-by,
# Endorsed-by, Co-authored-by, ...) - rather than a closed list, so a forged
# endorsement under a novel trailer name cannot slip through. No end-of-line
# anchor, so a trailing comment after the address cannot hide the trailer.
IDENTITY_TRAILER_RE = re.compile(
    r"^([A-Za-z][A-Za-z-]*-by):\s*(.+?)\s+<([^<>\s]+@[^<>\s]+)>",
    re.IGNORECASE | re.MULTILINE)


def normalize_subject(subject):
    """Canonicalise a subject for prefix matching.

    Collapses internal whitespace runs and removes whitespace before a colon,
    so open-ended spacing variants ('UPSTREAM :', 'feat  (x) :') reduce to one
    form the prefix rules can match. Case is handled by the rules themselves
    (re.IGNORECASE / lowercased tokens). The original subject is kept for
    display and the length check.
    """
    s = re.sub(r"\s+", " ", subject).strip()
    s = re.sub(r"\s+:", ":", s)
    return s


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
    """True for an auto-generated GitHub web-editor commit subject.

    A verb plus a single filename-like token (and nothing else) is the
    web-editor shape. "Filename-like" is judged by shape - a path, an
    extension, a "*file" name, an ALL-CAPS build file, or a known dotfile -
    rather than a closed allow-list, so files outside the set (Jenkinsfile,
    Doxyfile, BUILD, WORKSPACE, ...) are still caught while ordinary words
    (Update toolchain) are not.
    """
    if UPLOAD_RE.match(subject):
        return True
    m = WEBEDIT_VERB_RE.match(subject)
    if not m:
        return False
    token = m.group(2)
    if "." in token or "/" in token:                  # path or has an extension
        return True
    if token.lower() in WEBEDIT_KNOWN_FILES:          # Kconfig, Kbuild, ...
        return True
    if re.search(r"file$", token, re.IGNORECASE):     # Jenkinsfile, Doxyfile, ...
        return True
    if token.isupper() and len(token) >= 3:           # BUILD, WORKSPACE, COPYING
        return True
    return False


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

def check_commit(commit, cfg=None, pr_author=None):
    """Return the list of Findings for a single commit.

    pr_author is the GitHub login of the pull request submitter (API mode);
    when set, the GitHub-verified author/committer accounts are cross-checked
    against it. None disables those checks (git mode has no login data).
    """
    cfg = cfg or Config()
    out = []

    def add(rule, severity, message):
        out.append(Finding(rule=rule, severity=severity, message=message,
                           commit=commit.short_sha, subject=commit.subject))

    subject = commit.subject
    norm = normalize_subject(subject)

    # --- subject structure -------------------------------------------------
    if not subject.strip():
        add("subject-empty", "error", "Commit has an empty subject line.")
    else:
        # Two small closed vocabularies (Conventional Commits types, kernel
        # prefixes) are irreducible - they look like valid components but are
        # not. Everything else is decided by one positive check: a subject
        # that attempts a prefix must be the canonical lowercase-component
        # shape; this subsumes a missing space after the colon and a
        # capitalised or otherwise malformed prefix.
        m_type = CC_TYPE_RE.match(norm)
        is_cc = CC_SCOPE_RE.match(norm) or (
            m_type and m_type.group(1).lower() not in cfg.cc_allow_components)
        if is_cc:
            add("conventional-commit", "error",
                "Drop the Conventional Commits prefix; use a "
                "'component: imperative summary' subject.")
        elif KERNEL_PREFIX_RE.match(norm):
            add("kernel-prefix", "error",
                f"Drop the kernel-tree prefix '{norm.split(':', 1)[0]}:'; use "
                f"a 'component: summary' subject.")
        elif PREFIX_ATTEMPT_RE.match(norm) and not COMPONENT_CANONICAL_RE.match(norm):
            add("invalid-component-prefix", "error",
                "The text before the colon must be a lowercase component name "
                "followed by a space (e.g. 'linux-qcom: ...').")

        if FIXUP_RE.match(subject) or WIP_RE.match(subject):
            add("fixup-commit", "error",
                "Work-in-progress/fixup commit; squash it into the commit "
                "it belongs to.")

        # Auto-generated web-editor subjects are advisory: a bare imperative
        # is a valid subject, so "is this really a web edit" is a judgement
        # call. Web commits that matter are gated by identity-webclient.
        if is_webedit_subject(subject):
            add("webedit-subject", "warning",
                "Subject looks auto-generated by the GitHub web editor; write "
                "a descriptive 'component: summary' line.")

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

    # --- GitHub-verified author identity (API mode) -----------------------
    # GitHub maps each commit's author email to an account. If a commit is
    # authored by a real account other than the PR submitter, surface it:
    # outright authorship spoofing (e.g. committing as a maintainer) shows up
    # here. Unlinked emails resolve to no account ("") and are not flagged, to
    # avoid noise on the common case of committing with an off-GitHub email.
    # Flag only when the submitter is neither the author nor the committer and
    # the commit is not a backport: carrying someone else's patch (committing
    # it and adding your sign-off) and cherry-picks are legitimate.
    if (pr_author and commit.author_login
            and commit.author_login.lower() != pr_author.lower()
            and (commit.committer_login or "").lower() != pr_author.lower()
            and not CHERRY_PICK_RE.search(commit.message)):
        add("author-not-submitter", "warning",
            f"Commit authored by GitHub user '{commit.author_login}', not the "
            f"pull request submitter '{pr_author}'; confirm the identity.")

    # --- unverifiable co-trailers -----------------------------------------
    # Trust the author's address. Trust the committer's only when GitHub
    # confirms the committer is the PR submitter - the committer field is
    # otherwise attacker-controlled and can launder a forged trailer.
    own = {commit.author_email.lower()} if commit.author_email else set()
    if (commit.committer_email and pr_author and commit.committer_login
            and commit.committer_login.lower() == pr_author.lower()):
        own.add(commit.committer_email.lower())
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
        if pf.content is None:
            # The content fetch failed; do not silently skip the gate.
            out.append(Finding(
                rule="patch-unfetched", severity="warning",
                message=("Could not fetch this patch file to verify its "
                         "Upstream-Status header; check it manually."),
                path=pf.path, line=1))
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


def check_all(commits, patch_files=None, cfg=None, pr_author=None):
    """Run every enabled rule and return the full list of Findings."""
    cfg = cfg or Config()
    findings = []
    for c in commits:
        findings.extend(check_commit(c, cfg, pr_author))
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


def should_post_review(findings, approve_on_pass=False):
    """Whether to post a review at all.

    A clean pull request posts nothing - a "passed / no issues" comment is
    just noise. Set approve_on_pass to post an explicit APPROVE instead.
    """
    return bool(findings) or approve_on_pass


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
API_TIMEOUT = 12   # per-request socket timeout; a stalled connection fails
API_RETRIES = 4    # transient (timeout / 5xx / secondary-limit) retries, GET only


def _retry_after(err):
    try:
        return int(err.headers.get("Retry-After", ""))
    except (TypeError, ValueError, AttributeError):
        return None


def _api(method, url, token, data=None, accept="application/vnd.github+json"):
    """A GitHub API call with a socket timeout and retries.

    urllib has no default timeout, so without this a single stalled
    connection (intermittent on some networks) hangs the whole tool. Only
    idempotent GETs are retried; a POST is never retried, to avoid posting a
    review twice.
    """
    body = json.dumps(data).encode() if data is not None else None
    raw = accept.endswith("raw")
    attempts = API_RETRIES if method == "GET" else 1
    last = None
    for i in range(attempts):
        req = urllib.request.Request(url, data=body, method=method)
        if token:  # optional: public reads work unauthenticated (rate-limited)
            req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", accept)
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
                payload = resp.read()
                if raw:
                    return resp.status, payload.decode("utf-8", "replace"), resp.headers
                return resp.status, json.loads(payload or b"null"), resp.headers
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 500, 502, 503, 504) and i < attempts - 1:
                time.sleep(min(_retry_after(e) or 2 ** i, 20))
                last = e
                continue
            raise
        except (urllib.error.URLError, OSError) as e:  # timeout / DNS / reset
            if i < attempts - 1:
                time.sleep(0.5 * (2 ** i))
                last = e
                continue
            raise
    raise last  # pragma: no cover


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


def get_pr_author(repo, pr, token):
    """Return the GitHub login of the pull request submitter."""
    _, data, _ = _api("GET", f"{_API}/repos/{repo}/pulls/{pr}", token)
    return ((data or {}).get("user") or {}).get("login") or ""


def load_commits_api(repo, pr, token):
    data = _get_all(f"{_API}/repos/{repo}/pulls/{pr}/commits?per_page=100", token)
    commits = []
    for c in data:
        ca = c["commit"].get("author") or {}
        cc = c["commit"].get("committer") or {}
        # Top-level author/committer are the GitHub accounts the emails map
        # to (or null); the verified provenance the raw git metadata lacks.
        gh_a = c.get("author") or {}
        gh_c = c.get("committer") or {}
        commits.append(Commit(
            sha=c["sha"], parents=[p["sha"] for p in c.get("parents", [])],
            author_name=ca.get("name", ""), author_email=ca.get("email", ""),
            committer_name=cc.get("name", ""), committer_email=cc.get("email", ""),
            author_login=gh_a.get("login") or "",
            committer_login=gh_c.get("login") or "",
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
            # Surface the failure (content=None) instead of silently skipping,
            # so a fetch failure cannot bypass the Upstream-Status gate.
            content = None
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


def build_pending_payload(head_sha, findings):
    """A reviews-API payload with NO event, which creates a PENDING review.

    GitHub cannot pre-fill a comment via a URL, so instead we stage the
    findings as a draft review owned by the maintainer: the comments show up
    pre-populated in the PR, and the maintainer edits and submits them.
    """
    inline = [{"path": f.path, "line": f.line, "side": "RIGHT", "body": f.message}
              for f in findings if f.path and f.line]
    lines = ["Commit policy suggestions (draft - edit or delete any, then "
             "click Submit review):", ""]
    by_commit = {}
    for f in findings:
        if f.path:
            continue
        by_commit.setdefault((f.commit, f.subject), []).append(f)
    for (sha, subject), fs in by_commit.items():
        lines.append(f"Commit {sha} ({subject}):")
        for f in fs:
            lines.append(f"- {f.severity}, {f.rule}: {f.message}")
        lines.append("")
    payload = {"commit_id": head_sha, "body": "\n".join(lines).strip()}
    if inline:
        payload["comments"] = inline          # no "event" key => pending review
    return payload


def stage_pending_review(slug, pr, payload, token):
    """Create a pending (draft) review; fall back to body-only on a bad anchor."""
    url = f"{_API}/repos/{slug}/pulls/{pr}/reviews"
    try:
        _, data, _ = _api("POST", url, token, payload)
        return data
    except urllib.error.HTTPError as e:
        if "comments" in payload and e.code == 422:  # inline position rejected
            body_only = {k: v for k, v in payload.items() if k != "comments"}
            _, data, _ = _api("POST", url, token, body_only)
            return data
        raise


# --------------------------------------------------------------------------
# Interactive review (read-only maintainer evaluation tool)
# --------------------------------------------------------------------------
#
# Point the script at a repository or pull request URL to browse recent pull
# requests, run the checker against one through the API WITHOUT posting
# anything, and print the review the action would post plus a clickable link
# per finding so a maintainer can act on it by hand. Lets a project try the
# rules before wiring the action into CI.

def _token():
    t = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if t:
        return t
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception:
        return ""  # public repos are readable unauthenticated (rate-limited)


def parse_pr_url(url):
    """Return (owner, repo, pr_number_or_None) from a github.com URL."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/?#]+)(?:/(?:pull|pulls)/?"
                 r"(\d+)?)?", url.strip().rstrip("/"))
    if not m:
        raise ValueError(f"not a recognised GitHub URL: {url}")
    return m.group(1), m.group(2), (int(m.group(3)) if m.group(3) else None)


def _drop_drafts(items):
    """Drop draft pull requests; they are work-in-progress, not ready to review."""
    return [it for it in items if not it.get("draft")]


def list_open_prs(owner, repo, token, limit=10, page=1, sort="updated"):
    """One page of open, non-draft PRs, most-recently-active first by default.

    The list response already carries head.sha and user.login, so a per-PR
    metadata fetch is not needed to review them.
    """
    url = (f"{_API}/repos/{owner}/{repo}/pulls?state=open&sort={sort}"
           f"&direction=desc&per_page={limit}&page={page}")
    _, data, _ = _api("GET", url, token)
    return _drop_drafts(data)


def check_pr_item(slug, item, token, cfg):
    """Check a PR and load its discussion; returns (findings, discussion_text).

    Fetching the discussion here means the list tags can reflect only the
    findings reviewers have NOT already raised, and opening the PR (and going
    back to it) reuses the cached discussion instead of fetching again.
    """
    pr = item["number"]
    head_sha = (item.get("head") or {}).get("sha", "")
    pr_author = (item.get("user") or {}).get("login") or ""
    commits = load_commits_api(slug, pr, token)
    patch_files = (load_patch_files_api(slug, pr, head_sha, token)
                   if cfg.patch_check else [])
    findings = check_all(commits, patch_files, cfg, pr_author)
    if len(commits) >= 250:
        findings.append(Finding(
            rule="pr-too-large", severity="warning",
            message="250+ commits; only the first 250 were checked."))
    try:
        disc = fetch_discussion_text(slug, pr, token)
    except (urllib.error.URLError, OSError):
        disc = ""
    return findings, disc


def check_pr_items(slug, items, token, cfg, workers=6):
    """Check a page of PRs concurrently; returns {number: (status, value)}."""
    out = {}
    if not items:
        return out
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        futs = {ex.submit(check_pr_item, slug, it, token, cfg): it["number"]
                for it in items}
        for fut in as_completed(futs):
            n = futs[fut]
            try:
                out[n] = ("ok", fut.result())
            except Exception as e:  # one PR failing must not sink the page
                out[n] = ("err", str(e))
    return out


def review_pr_readonly(owner, repo, pr, token, cfg):
    slug = f"{owner}/{repo}"
    _, meta, _ = _api("GET", f"{_API}/repos/{slug}/pulls/{pr}", token)
    findings, disc = check_pr_item(slug, meta, token, cfg)
    return meta, findings, disc


def _pr_tag(status, findings):
    """A fixed-width, colour-coded at-a-glance status tag for a PR line."""
    if status != "ok":
        label, code = "[?]", "2"
    else:
        e = sum(1 for f in findings if f.severity == "error")
        w = sum(1 for f in findings if f.severity == "warning")
        if e:
            label, code = f"[err {e}]", "1;31"
        elif w:
            label, code = f"[warn {w}]", "33"
        else:
            label, code = "[ok]", "32"
    return _style(label.ljust(9), code)


def comment_url(owner, repo, pr, finding):
    """A URL where a maintainer can leave the comment for this finding."""
    if finding.path and finding.line:
        h = hashlib.sha256(finding.path.encode()).hexdigest()
        return (f"https://github.com/{owner}/{repo}/pull/{pr}/files"
                f"#diff-{h}R{finding.line}")
    if finding.commit and finding.commit != "(working)":
        return (f"https://github.com/{owner}/{repo}/pull/{pr}/commits/"
                f"{finding.commit}")
    return f"https://github.com/{owner}/{repo}/pull/{pr}"


def _style(text, code):
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def _link(url, label=None):
    """Wrap text in an OSC 8 terminal hyperlink when stdout is a TTY.

    Terminals that support OSC 8 (iTerm2, kitty, WezTerm, VTE/GNOME Terminal,
    Windows Terminal, ...) render the label as a clickable link to url; the
    rest ignore the escape and just show the label. The label defaults to the
    URL so even an unsupported terminal shows a (usually click-through) URL.
    Set NO_HYPERLINKS=1 to disable.
    """
    label = url if label is None else label
    if sys.stdout.isatty() and not os.environ.get("NO_HYPERLINKS"):
        return f"\033]8;;{url}\033\\{label}\033]8;;\033\\"
    return label


# Per-rule phrases that indicate a human reviewer already raised the issue.
# Heuristic and deliberately on the specific side for the gating rules, to
# avoid hiding a genuinely new finding. Matched as lowercase substrings.
RULE_KEYWORDS = {
    "signoff-missing": ("signed-off-by", "sign-off", "sign off", "signoff",
                        "dco", "commit -s", "--signoff"),
    "signoff-malformed": ("signed-off-by", "sign-off", "signoff", "malformed",
                          "dco"),
    "signoff-author-mismatch": ("signed-off-by", "sign-off", "dco",
                                "author email", "match the author"),
    "kernel-prefix": ("fromlist", "fromgit", "upstream:", "backport:",
                      "kernel prefix", "drop the prefix", "tree prefix"),
    "conventional-commit": ("conventional commit", "feat:", "fix(",
                            "commit message format", "commit prefix",
                            "semantic commit"),
    "invalid-component-prefix": ("component prefix", "lowercase",
                                 "space after the colon", "commit subject",
                                 "subject prefix", "subject line"),
    "merge-commit": ("merge commit", "rebase", "don't merge", "do not merge"),
    "fixup-commit": ("squash", "fixup", "work in progress", "wip commit",
                     "[wip]"),
    "webedit-subject": ("web editor", "web ui", "github ui", "web interface"),
    "identity-webclient": ("noreply", "real name", "real email", "web editor",
                           "your identity"),
    "identity-noreply": ("noreply", "real email"),
    "author-not-submitter": ("authored by", "not the author", "spoof",
                             "impersonat", "identity"),
    "unverified-cotrailer": ("acked-by", "reviewed-by", "co-authored",
                             "tested-by", "trailer", "fabricat"),
    "subject-too-long": ("too long", "shorten the subject", "72 char",
                         "50 char", "subject length", "line wrap"),
    "body-empty": ("explain why", "describe the", "empty commit message",
                   "no commit message", "real commit message", "message body"),
    "patch-upstream-status": ("upstream-status", "upstream status"),
}


def already_raised(finding, text):
    """True if the discussion text looks like a reviewer raised this rule."""
    return any(kw in text for kw in RULE_KEYWORDS.get(finding.rule, ()))


def partition_already_raised(findings, text):
    """Split findings into (new, already_raised) against discussion text."""
    new, raised = [], []
    for f in findings:
        (raised if (text and already_raised(f, text)) else new).append(f)
    return new, raised


def fetch_discussion_text(slug, pr, token):
    """Lowercased text of the PR's human comments and reviews.

    Skips this tool's own posted reviews so it does not match itself.
    """
    parts = []
    for path in (f"issues/{pr}/comments", f"pulls/{pr}/reviews"):
        try:
            items = _get_all(f"{_API}/repos/{slug}/{path}?per_page=100", token)
        except (urllib.error.URLError, OSError):
            continue
        for it in items:
            body = it.get("body") or ""
            if "commit policy check" in body.lower():
                continue  # our own bot review
            parts.append(body)
    return "\n".join(parts).lower()


def _finding_line(owner, repo, pr, f):
    sev = _style("ERROR", "31") if f.severity == "error" else _style("warn", "33")
    url = comment_url(owner, repo, pr, f)
    print(f"    [{sev}] {f.rule}: {f.message}")
    print(f"      open:  {_link(url, _style(url, '36'))}")


def render_cli_review(owner, repo, pr, meta, findings, discussion_text=None):
    title = meta.get("title", "")
    author = (meta.get("user") or {}).get("login", "?")
    pr_url = f"https://github.com/{owner}/{repo}/pull/{pr}"
    new, raised = partition_already_raised(findings, discussion_text or "")
    errs = sum(1 for f in findings if f.severity == "error")
    warns = sum(1 for f in findings if f.severity == "warning")
    verdict = ("REQUEST CHANGES" if errs else
               "COMMENT" if findings else "APPROVE / no issues")
    note = f" — {len(raised)} already raised by reviewers" if raised else ""
    print()
    print(_link(pr_url, _style(f"PR #{pr}: {title}", "1")))
    print(_style(f"by {author}  |  ", "2") + _link(pr_url, _style(pr_url, "2")))
    print(_style(f"Verdict the action would post: {verdict}  "
                 f"({errs} error(s), {warns} warning(s){note})", "1"))

    if not findings:
        print(_style("No issues found.", "32"))
        return

    if new:
        print(_style("\nIssues not yet raised by reviewers "
                     "(paste the text at each link):", "1"))
        groups, files = {}, []
        for f in new:
            if f.path:
                files.append(f)
            else:
                groups.setdefault((f.commit, f.subject), []).append(f)
        for (sha, subject), fs in groups.items():
            print(f"\n  {_style('commit ' + sha, '1')}  {subject}")
            for f in fs:
                _finding_line(owner, repo, pr, f)
        for f in files:
            print(f"\n  {_style(f.path, '1')}")
            _finding_line(owner, repo, pr, f)
    else:
        print(_style("\nAll findings were already raised by reviewers; "
                     "nothing new to add.", "2"))

    if raised:
        rule_list = ", ".join(sorted({f.rule for f in raised}))
        print(_style(f"\nAlready raised by reviewers (hidden): {rule_list}", "2"))


def resolve_choice(choice, order):
    """Map a browse-prompt input to an action (pure, so it is unit-tested).

    Returns one of: ("quit",), ("refresh",), ("more",),
    ("review", pr_number), or ("error", message).

    A bare in-range number is a 1-based list POSITION and resolves to the PR
    at order[n-1] (so it hits the cache); "#NNN" - or a bare number past the
    end of the list - is an explicit PR NUMBER.
    """
    c = choice.strip()
    low = c.lower()
    if low in ("q", "quit"):
        return ("quit",)
    if low in ("r", "refresh"):
        return ("refresh",)
    if low in ("b", "back"):
        return ("back",)
    if low in ("s", "stage"):
        return ("stage",)
    if c == "":
        return ("more",)
    num = c.lstrip("#")
    if not num.isdigit():
        return ("error", "Enter a list position, #NNN for a PR, Enter for "
                         "more, s stage, b back, r refresh, or q quit.")
    n = int(num)
    if not c.startswith("#") and 1 <= n <= len(order):
        return ("review", order[n - 1])
    return ("review", n)


def interactive_review(url, cfg):
    token = _token()
    try:
        owner, repo, pr0 = parse_pr_url(url)
    except ValueError as e:
        sys.stderr.write(f"{e}\n")
        return 2
    slug = f"{owner}/{repo}"
    if not token:
        sys.stderr.write("Note: no GITHUB_TOKEN / gh login found; using "
                         "unauthenticated API (low rate limit).\n")

    cache = {}       # number -> (item, status, findings, disc); re-open instant
    order = []       # PR numbers in display order, so a bare N selects by position
    history = []     # reviewed PR numbers, for the 'b' back command
    current = {}     # the last reviewed PR, for the 's' stage command
    bg = ThreadPoolExecutor(max_workers=1)  # prefetch the next page

    def load_page(page):
        items = list_open_prs(owner, repo, token, 10, page, "updated")
        return items, check_pr_items(slug, items, token, cfg)

    def show(items, results, base):
        for i, it in enumerate(items, base + 1):
            n = it["number"]
            status, val = results.get(n, ("err", None))
            findings, disc = val if status == "ok" else ([], "")
            cache[n] = (it, status, findings, disc)
            order.append(n)
            # Tag reflects only findings reviewers have NOT already raised.
            new, _ = partition_already_raised(findings, disc)
            who = (it.get("user") or {}).get("login", "?")
            when = (it.get("updated_at") or "")[:10]
            head = _link(f"https://github.com/{slug}/pull/{n}",
                         _style(f"#{n}", "1") + f"  {it['title'][:56]}")
            print(f"{_pr_tag(status, new)} {_style(f'{i:>3}.', '2')} {head}")
            print(_style(f"{'':>15}by {who} · updated {when}", "2"))
        return base + len(items)

    def review(n):
        if n in cache and cache[n][1] == "ok":
            meta, _, findings, disc = cache[n]
        else:
            try:
                meta, findings, disc = review_pr_readonly(
                    owner, repo, n, token, cfg)
            except urllib.error.HTTPError as e:
                sys.stderr.write(f"Could not load PR #{n}: {e.code} {e.reason}\n")
                return
        render_cli_review(owner, repo, n, meta, findings, disc)
        current.update(pr=n, meta=meta, findings=findings, disc=disc)
        if token and partition_already_raised(findings, disc)[0]:
            print(_style("(press s to stage these as a draft review on your "
                         "GitHub review queue)", "2"))

    try:
        print(_style(f"\ncommit-policy review (read-only) — {slug}", "1"))
        if pr0 is not None:        # a direct .../pull/N URL: review it first
            review(pr0)
        print(_style("Fetching recent pull requests and checking them in "
                     "parallel, one moment...", "2"))
        try:
            page = 1
            items, results = load_page(page)
        except urllib.error.HTTPError as e:
            sys.stderr.write(f"API error: {e.code} {e.reason}\n")
            return 1
        if not items:
            print("No open pull requests.")
            return 0
        shown = show(items, results, 0)
        prefetch = bg.submit(load_page, page + 1)

        while True:
            try:
                choice = input(_style(
                    "\n[Enter] more · N/#NNN review · s stage · b back · "
                    "r refresh · q quit: ", "1")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0

            action = resolve_choice(choice, order)
            kind = action[0]

            if kind == "quit":
                return 0

            if kind == "error":
                print(action[1])
                continue

            if kind == "refresh":
                cache.clear()
                order.clear()
                print(_style("Refreshing (most recently active first)...", "2"))
                try:
                    page = 1
                    items, results = load_page(page)
                except urllib.error.HTTPError as e:
                    sys.stderr.write(f"API error: {e.code} {e.reason}\n")
                    continue
                shown = show(items, results, 0)
                prefetch = bg.submit(load_page, page + 1)
                continue

            if kind == "more":   # Enter = load more (continuous scroll)
                try:
                    items, results = prefetch.result()
                except Exception:
                    try:
                        items, results = load_page(page + 1)
                    except urllib.error.HTTPError as e:
                        sys.stderr.write(f"API error: {e.code} {e.reason}\n")
                        continue
                if not items:
                    print(_style("(no more open pull requests)", "2"))
                    continue
                page += 1
                shown = show(items, results, shown)
                prefetch = bg.submit(load_page, page + 1)
                continue

            if kind == "back":
                if len(history) >= 2:
                    history.pop()                 # drop the current review
                    review(history[-1])
                elif history:
                    review(history[-1])           # only one; re-show it
                else:
                    print(_style("No previous review.", "2"))
                continue

            if kind == "stage":
                if not current:
                    print(_style("Review a PR first, then 's' to stage it.", "2"))
                    continue
                if not token:
                    print(_style("Staging needs a GitHub login (gh auth login "
                                 "or GITHUB_TOKEN).", "2"))
                    continue
                cn = current["pr"]
                new, _ = partition_already_raised(current["findings"],
                                                  current["disc"])
                if not new:
                    print(_style("Nothing new to stage.", "2"))
                    continue
                head_sha = (current["meta"].get("head") or {}).get("sha", "")
                try:
                    stage_pending_review(
                        slug, cn, build_pending_payload(head_sha, new), token)
                except urllib.error.HTTPError as e:
                    detail = e.read().decode(errors="replace")[:200]
                    sys.stderr.write(f"Could not stage review for #{cn}: "
                                     f"{e.code} {e.reason} {detail}\n")
                else:
                    url = f"https://github.com/{slug}/pull/{cn}/files"
                    print(_style(f"Draft review for #{cn} staged on your GitHub "
                                 f"review queue. Edit and submit it here:", "32"))
                    print("  " + _link(url, _style(url, "36")))
                continue

            n = action[1]  # kind == "review"
            review(n)
            if not history or history[-1] != n:
                history.append(n)
    finally:
        bg.shutdown(wait=False, cancel_futures=True)


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
    p.add_argument("url", nargs="?",
                   help="GitHub repo or pull request URL: launches an "
                        "interactive, read-only review (nothing is posted)")
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

    if args.url:  # interactive read-only review of a PR URL
        code = interactive_review(args.url, cfg) or 0
        # Hard-exit so an in-flight background prefetch cannot keep the process
        # alive: concurrent.futures joins its (non-daemon) workers at exit, and
        # on a flaky network those can stall for a long time.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)

    pr_author = None
    if args.api:
        if not (args.repo and args.pr):
            p.error("--api needs --repo and --pr")
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            p.error("--api needs $GITHUB_TOKEN")
        commits = load_commits_api(args.repo, args.pr, token)
        pr_author = get_pr_author(args.repo, args.pr, token)
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

    findings = check_all(commits, patch_files, cfg, pr_author)
    if args.api and len(commits) >= 250:
        findings.append(Finding(
            rule="pr-too-large", severity="warning",
            message=("This pull request has 250 or more commits; only the "
                     "first 250 were retrieved and checked.")))

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
        if not should_post_review(findings, args.approve_on_pass):
            sys.stderr.write("No issues found; not posting a review.\n")
        else:
            payload = build_review(findings, args.approve_on_pass, cfg.guidelines)
            status, event = post_review(args.repo, args.pr, head_sha, payload, token)
            sys.stderr.write(f"Posted {event} review (HTTP {status}).\n")

    return 1 if (args.fail_on_error and has_errors(findings)) else 0


if __name__ == "__main__":
    sys.exit(main())
