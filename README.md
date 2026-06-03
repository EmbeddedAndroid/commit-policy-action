# commit-policy-action

A reusable GitHub workflow that reviews a pull request's commits against an
OpenEmbedded / Yocto layer contribution policy (the style documented in a
repository's `AGENTS.md`) and posts the result as a pull request review.

It is deterministic, has no runtime dependencies beyond Python 3 and the
GitHub API, needs no API secret, and never checks out or runs the pull
request's code. It is meant to be shared across repositories that follow the
same review pattern (for example the `qualcomm-linux` Yocto layers).

## What it checks

Blocking (the review requests changes and the job fails):

| Rule | What it catches |
|------|-----------------|
| `kernel-prefix` | `FROMLIST:` / `UPSTREAM:` / `BACKPORT:` / `FROMGIT:` subjects (any case, with or without a space before the colon) |
| `conventional-commit` | Conventional Commits subjects (`feat:`, `fix(scope):`, `feat (scope):`, `docs:`, ...) |
| `component-colon-space` | `component:summary` missing the space after the colon |
| `webedit-subject` | GitHub web-editor subjects (`Create file.yml`, `Update Kconfig`, `... files via upload`) |
| `fixup-commit` | `fixup!` / `squash!` / `WIP` commits left in the series |
| `merge-commit` | merge commits in the series (rebase instead) |
| `signoff-missing` / `signoff-malformed` / `signoff-author-mismatch` | missing, malformed, or non-author Signed-off-by |
| `identity-webclient` | numbered `NNNN+user@users.noreply.github.com` identities |
| `patch-upstream-status` | added `.patch` files with a missing or invalid `Upstream-Status` value |

Advisory (warnings; surfaced but do not fail the job):

`subject-too-long`, `body-empty`, `identity-noreply`, `signoff-name-mismatch`,
and `unverified-cotrailer` (a `Signed-off-by` / `Acked-by` / `Reviewed-by` /
`Co-authored-by` / ... for someone other than the author or committer, which a
maintainer must confirm).

Semantic judgements - whether the body explains why, whether the subject
truthfully describes the diff, whether unrelated changes are bundled - are left
to human review.

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
