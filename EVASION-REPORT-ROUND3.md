# Commit-policy checker: evasion report, round 3 (2026-06-04)

Third red-team pass. Since round 2 the checker was extracted from
`meta-qcom/ci/` into this standalone reusable action
(`EmbeddedAndroid/commit-policy-action`, tag `v1`), and meta-qcom's
`review-check` now consumes it as a `workflow_call` caller. CI runs the checker
in **API mode** (`--api`), reading the PR through the GitHub REST API with no
checkout of the reviewed repo.

## Round-2 fixes verified closed

Re-running the round-2 branches against the current checker confirms they gate:
`Co-authored-by`/`Reported-by`/`Suggested-by` now raise `unverified-cotrailer`,
the trailing-comment escape is closed (the `$` anchor was dropped),
`Update Kconfig`/`Create Dockerfile` are caught via `WEBEDIT_KNOWN_FILES`, and
`feat (wifi):` is caught (`CC_SCOPE_RE` now allows whitespace before the scope).
Good.

## New findings

Three new bypasses, all confirmed live (PRs #12, #13, #14) — each exits 0, the
check goes green, only a non-blocking `COMMENTED` review is posted.

| PR | Branch | Bypass | Severity |
|----|--------|--------|----------|
| #12 | `demo/identity-spoof` | full commit-identity spoofing | high |
| #13 | `demo/nonstandard-trailer` | forged endorsement via a non-listed trailer | medium |
| #14 | `demo/webedit-known-files` | web-editor subject on an extensionless file outside the set | low |

---

## PR #12 — Commit identity spoofing produces zero findings (high)

This is the headline. Every identity rule checks only **internal consistency**,
and every git identity field it consults is attacker-controlled.

```python
if commit.author_email and commit.author_email.lower() not in sob_emails:
    add("signoff-author-mismatch", "error", ...)
...
own = {e.lower() for e in (commit.author_email, commit.committer_email) if e}
others = [... for ... in IDENTITY_TRAILER_RE.findall(commit.message)
          if em.lower() not in own]
```

### 12a. Spoof authorship outright

Authoring *and* signing off as a maintainer satisfies every rule:

```
Author:     Bjorn Andersson <andersson@kernel.org>
Signed-off-by: Bjorn Andersson <andersson@kernel.org>
```

`author_email == signoff_email` so `signoff-author-mismatch` is silent; the
identity is the author's own, so `unverified-cotrailer` is silent; the address
is not a noreply, so no identity rule fires. **Zero findings.**

This is strictly worse than the round-1 forged co-trailer, which at least warns.
Moving the forgery into the *primary author identity* warns about nothing.

**Confirmed on the live PR.** GitHub's own API resolved the spoofed commit to
the **real** maintainer account, while the PR was opened by `EmbeddedAndroid`:

```
git-author: Bjorn Andersson <andersson@kernel.org>
  -> resolved author.login: andersson      (the real maintainer's account)
  -> PR submitted by:        EmbeddedAndroid
```

So GitHub credited the contribution graph to the real `andersson`, and the
mismatch between `author.login` and the PR author is exactly the signal needed
to catch this — but the checker never looks at it.

### 12b. Launder a forged sign-off through the committer field

A forged third-party `Signed-off-by` normally raises `unverified-cotrailer`.
But the suppression set is `{author_email, committer_email}`, and the committer
is just as attacker-controlled as the author. Setting the committer to the
forged identity moves it into `own`, silencing the warning:

```
Author:    Tyler Baker <tyler.baker@oss.qualcomm.com>
Committer: Greg Kroah-Hartman <gregkh@kernel.org>
Signed-off-by: Tyler Baker <tyler.baker@oss.qualcomm.com>
Signed-off-by: Greg Kroah-Hartman <gregkh@kernel.org>   <- forged, but == committer, so not flagged
```

**Why it matters:** a deterministic tool genuinely cannot *prove* a git identity
is real — but it is currently not even using the verification data GitHub hands
it for free. The `own` set treating the committer as trusted makes it worse: the
committer field becomes a laundering channel for forged trailers.

**Fix direction:**

- In API mode, the `pulls/{pr}/commits` response includes `author.login` and
  `committer.login` (the GitHub account each email maps to, or `null`).
  Currently the loader reads only `commit.author`/`commit.committer` (raw git
  metadata) and throws the verified `.login` fields away. Capture them. Warn
  when a commit's `author.login` is `null` (email maps to no account) or differs
  from the PR author, and surface the spoof.
- Do not treat the committer as automatically trusted in the `own` set for the
  cotrailer check; or only trust it when `committer.login` matches the PR author.
- Document that absolute identity proof remains a human-review item — but the
  `author.login` vs PR-author cross-check is deterministic and would have caught
  12a outright.

---

## PR #13 — Forged endorsement via a non-listed trailer (medium)

```python
IDENTITY_TRAILER_RE = re.compile(
    r"^(Signed-off-by|Co-developed-by|Co-authored-by|Reviewed-by|Acked-by"
    r"|Tested-by|Reported-by|Suggested-by):\s*(.+?)\s+<([^<>\s]+@[^<>\s]+)>",
    re.IGNORECASE | re.MULTILINE)
```

The round-2 fix expanded this list and removed the end-of-line anchor, closing
the round-2 cases. But it is still a closed enumeration of trailer names, so a
fabricated endorsement under any other trailer reads as human attribution yet
raises nothing:

```
Approved-by: Bjorn Andersson <andersson@kernel.org>
Endorsed-by: Greg Kroah-Hartman <gregkh@kernel.org>
```

Zero findings.

**Fix direction:** match any `Word[-Word]*-by:` trailer generically (e.g.
`^[A-Z][A-Za-z-]*-by:\s*...<email>`), and run all of them through the
not-author/committer check. This converts the rule from an allow-list to a
pattern and removes the whack-a-mole.

---

## PR #14 — Web-editor subject on an extensionless file outside the set (low)

```python
WEBEDIT_KNOWN_FILES = frozenset({"kconfig", "kbuild", "dockerfile", ...})
def is_webedit_subject(subject):
    ...
    if "." in token or "/" in token:
        return True
    return token.lower() in WEBEDIT_KNOWN_FILES
```

The round-2 fix added extensionless detection via a known-files set, closing
`Update Kconfig`. But the set is, again, an allow-list, so a web-editor commit
on a root-level extensionless file *outside* the set keeps its auto-generated
subject and evades:

```
Create Jenkinsfile          # also: Update Doxyfile, Update Procfile,
                            #       Update BUILD, Update WORKSPACE, Update Justfile
```

`jenkinsfile` is not in `WEBEDIT_KNOWN_FILES`, so `is_webedit_subject` returns
`False`. AGENTS.md bans web-editor authorship.

**Fix direction:** the set will always be incomplete. Treat
`Update|Create|Delete <single-bare-token>` as a web-editor subject by shape (a
verb plus exactly one filename-like token and nothing else is already very
unlike a real `component: summary` subject), and lean on `identity-webclient`
for the residue. At minimum, acknowledge in a comment that the set is
best-effort.

---

## Also noted (not demonstrated)

Structural properties of API mode worth a look, not turned into PRs because they
need impractical inputs or a second account:

- **`pulls/{pr}/commits` caps at 250 commits.** A PR with more than 250 commits
  has its tail silently omitted from the review (the endpoint does not page past
  250). A bad commit buried past #250 would not be checked. The
  [List commits] endpoint returns the full set if completeness matters.
- **`load_patch_files_api` swallows a failed content fetch** (`except
  HTTPError: continue`). If the contents API returns non-200 for a `.patch`
  file at `head_sha` — plausible for some cross-fork or oversized-blob cases —
  the file is skipped and its `Upstream-Status` is never checked. Worth
  confirming whether a cross-fork PR's head sha always resolves under the base
  repo's contents API; if not, the patch gate is bypassable from a fork. (Our
  same-repo demo branches resolve fine, so this is a hypothesis, not a
  confirmed bypass.)

---

## Summary

Round-2 fixes hold. The recurring theme is now explicit and worth calling out as
a design point rather than a list of one-off regexes:

1. **Allow-lists keep leaving adjacent inputs uncovered** (#13 trailer names,
   #14 filenames) — the durable fix is pattern-by-shape, not enumeration.
2. **Identity rules only check internal consistency** (#12). The single
   highest-value change this round is to *use the GitHub-verified
   `author.login`/`committer.login` that API mode already fetches and currently
   discards*, and cross-check it against the PR author. That deterministically
   catches outright author spoofing (12a), which today produces zero findings.

Recommend fixing #12 first (it is the most serious and the fix is concrete and
deterministic), then #13, then #14, with a regression fixture for each.

## Reproduce locally

```sh
CHK=commit_policy_check.py    # this repo
for b in identity-spoof nonstandard-trailer webedit-known-files; do
  echo "== $b =="
  python3 "$CHK" --base review-check --head "origin/demo/$b" \
    --repo-dir /path/to/meta-qcom --cc-allow-components ci
done
```

Each prints "no issues found" (exit 0) today.
