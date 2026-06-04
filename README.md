# commit-policy-action

A reusable GitHub workflow that reviews a pull request's commits against an
OpenEmbedded / Yocto layer contribution policy (the style documented in a
repository's `AGENTS.md`) and posts the result as a pull request review.

It is deterministic, has no runtime dependencies beyond Python 3 and the
GitHub API, needs no API secret, and never checks out or runs the pull
request's code. It is meant to be shared across repositories that follow the
same review pattern (for example the `qualcomm-linux` Yocto layers).

## What it checks

The rules split into a **gate** (decidable from the commit text plus an
external anchor; these block) and **advisory** warnings (things a deterministic
tool cannot prove; surfaced for a human, never block).

Gate (review requests changes, job fails):

| Rule | What it catches |
|------|-----------------|
| `conventional-commit` | Conventional Commits subjects (`feat:`, `fix(scope):`, `feat (scope):`, `docs:`, ...) |
| `kernel-prefix` | `FROMLIST:` / `UPSTREAM:` / `BACKPORT:` / `FROMGIT:` (any case/spacing) |
| `invalid-component-prefix` | a prefix that is not a canonical `lowercase-component: summary` (capitalised, missing space after the colon, stray punctuation) |
| `fixup-commit` | `fixup!` / `squash!` / `WIP` commits |
| `merge-commit` | merge commits in the series |
| `signoff-missing` / `signoff-malformed` / `signoff-author-mismatch` | missing, malformed, or non-author Signed-off-by |
| `identity-webclient` | numbered `NNNN+user@users.noreply.github.com` identities |
| `patch-upstream-status` | added `.patch` files with a missing or invalid `Upstream-Status` value |

Advisory (warnings; surfaced, never block):

`subject-too-long`, `webedit-subject` (auto-generated web-editor subject),
`body-empty`, `identity-noreply`, `signoff-name-mismatch`, `author-not-submitter`
(commit authored by a GitHub account other than the PR submitter),
`unverified-cotrailer` (a `*-by:` trailer for someone other than the author or
committer), `patch-unfetched`, and `pr-too-large`.

Two design choices keep the gate from turning into whack-a-mole. Subject prefix
rules normalise whitespace and case once, then check the *positive* canonical
shape rather than blacklisting bad variants - so an unseen decorated variant is
simply "not the good shape." Identity is anchored to the GitHub-verified
`author.login` (API mode) rather than the attacker-controlled commit text.
Coverage is held by unit fixtures, property-based fuzzing
(`tests/test_fuzz.py`), and a labelled-corpus precision/recall gate
(`corpus_eval.py`, `tests/test_corpus.py`) - so "did it converge" is a number,
not "did a red-teamer find another string."

Semantic judgements - whether the body explains why, whether the subject
truthfully describes the diff - remain human review.

## Usage

Add a small caller workflow to the consuming repository (see
[`examples/commit-policy.yml`](examples/commit-policy.yml)):

```yaml
name: Commit Policy
on:
  pull_request_target:
    branches: [master]
permissions:
  contents: read
  pull-requests: write
jobs:
  commit-policy:
    uses: EmbeddedAndroid/commit-policy-action/.github/workflows/commit-policy.yml@v1
    with:
      action-ref: v1
      cc-allow-components: "ci"
```

`pull_request_target` is required so the token can post a review on pull
requests from forks. Set `permissions: pull-requests: write` on the caller so
the reused workflow inherits it.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `action-ref` | `main` | Ref of this repo the checker runs from; pin to the same tag/sha you call. |
| `cc-allow-components` | `ci` | Component prefixes allowed despite matching a Conventional Commits type. |
| `subject-max-length` | `80` | Soft subject-length warning threshold. |
| `valid-upstream-status` | `submitted,backport,pending,inappropriate,denied,accepted,inactive-upstream` | Accepted `Upstream-Status` values. |
| `disable-rules` | (none) | Comma list of rule ids to skip. |
| `guidelines` | `AGENTS.md` | Doc name cited in the review body. |
| `patch-check` | `true` | Check `Upstream-Status` on added patch files. |
| `post-review` | `true` | Post the result as a review. |
| `approve-on-pass` | `false` | Submit an APPROVE review when clean. |
| `fail-on-error` | `true` | Fail the job on a blocking issue. |

## Try it before deploying (interactive review)

Point the script at a repository or pull-request URL to evaluate the rules
against real pull requests without posting anything - a way to see what the
action would do before wiring it into CI:

```sh
python3 commit_policy_check.py https://github.com/qualcomm-linux/meta-qcom/pulls
```

It lists the ten most recent open pull requests; pick one (by list number or
`#NNN`) and it prints the review the action would post, plus a link and the
ready-to-paste text for each finding so a maintainer can leave the comments by
hand. Pass a specific pull-request URL (`.../pull/123`) to review it directly.
A `GITHUB_TOKEN` or `gh` login is used when present (recommended, to avoid API
rate limits); public repositories also work unauthenticated.

## Running locally

The checker is a single self-contained script. Against a local branch:

```sh
python3 commit_policy_check.py --base origin/master --head HEAD
```

Against a pull request through the API:

```sh
GITHUB_TOKEN=... python3 commit_policy_check.py --api --repo owner/name --pr 123
```

## Tests

```sh
python3 -m pytest tests/ -q
```

The fixtures are real offending and compliant commits, plus regression cases
for every recorded evasion attempt.
