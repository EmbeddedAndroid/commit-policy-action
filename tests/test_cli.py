# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# Tests for the interactive review CLI helpers. These lock the bugs found
# while using the tool: a list position being mistaken for a PR number (which
# caused a 404, a cache miss / slow re-fetch, and the wrong review with no
# warning shown), and the clickable-URL handling.

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import commit_policy_check as cp  # noqa: E402


# --------------------------------------------------------------------------
# resolve_choice: list position vs explicit PR number (the headline bug).
# --------------------------------------------------------------------------

# Display order: list positions 1..4 map to these PR numbers.
ORDER = [2347, 2348, 2251, 2346]


def test_bare_number_is_a_list_position_not_a_pr_number():
    # Typing "4" must open the PR at position 4 (#2346), NOT PR #4.
    assert cp.resolve_choice("4", ORDER) == ("review", 2346)
    assert cp.resolve_choice("1", ORDER) == ("review", 2347)


def test_hash_number_is_an_explicit_pr_number():
    # "#2346" is the PR number even though 2346 is not a list position.
    assert cp.resolve_choice("#2346", ORDER) == ("review", 2346)
    # "#4" is PR #4, not list position 4.
    assert cp.resolve_choice("#4", ORDER) == ("review", 4)


def test_bare_out_of_range_number_is_a_pr_number():
    # 2334 is past the end of the list, so it is treated as a PR number.
    assert cp.resolve_choice("2334", ORDER) == ("review", 2334)


def test_position_resolves_to_cached_pr_no_refetch():
    # The bug also made reviews slow: a position missed the cache and
    # re-fetched. With the fix the position resolves to the cached PR number.
    warn = cp.Finding(rule="subject-too-long", severity="warning",
                      message="too long", commit="abc123")
    cache = {2346: ({"title": "x"}, "ok", [warn])}
    _, pr = cp.resolve_choice("4", ORDER)        # position 4 -> #2346
    assert pr in cache and cache[pr][1] == "ok"   # cache hit, no network
    assert cache[pr][2] == [warn]                 # the warning is present


def test_navigation_words():
    assert cp.resolve_choice("", ORDER) == ("more",)
    assert cp.resolve_choice("q", ORDER)[0] == "quit"
    assert cp.resolve_choice("quit", ORDER)[0] == "quit"
    assert cp.resolve_choice("r", ORDER)[0] == "refresh"
    assert cp.resolve_choice("  refresh ", ORDER)[0] == "refresh"


def test_garbage_is_an_error_not_a_review():
    assert cp.resolve_choice("foo", ORDER)[0] == "error"
    assert cp.resolve_choice("12abc", ORDER)[0] == "error"


def test_back_command():
    assert cp.resolve_choice("b", ORDER) == ("back",)
    assert cp.resolve_choice("back", ORDER) == ("back",)
    assert cp.resolve_choice(" B ", ORDER) == ("back",)


def test_stage_command():
    assert cp.resolve_choice("s", ORDER) == ("stage",)
    assert cp.resolve_choice("stage", ORDER) == ("stage",)


def test_build_pending_payload_creates_a_draft():
    pf = cp.Finding(rule="patch-upstream-status", severity="error",
                    message="missing header", path="a/x.patch", line=1)
    cf = cp.Finding(rule="kernel-prefix", severity="error",
                    message="Drop the FROMLIST prefix", commit="abc123",
                    subject="x: y")
    p = cp.build_pending_payload("HEADSHA", [pf, cf])
    assert "event" not in p                       # no event => pending/draft
    assert p["commit_id"] == "HEADSHA"
    assert p["comments"][0]["path"] == "a/x.patch"  # patch finding -> inline
    assert "kernel-prefix" in p["body"]             # commit finding -> body
    assert "draft" in p["body"].lower()


def test_empty_order_falls_back_to_pr_number():
    assert cp.resolve_choice("5", []) == ("review", 5)


# --------------------------------------------------------------------------
# The review view must show warnings (not only errors).
# --------------------------------------------------------------------------

def _meta():
    return {"title": "ci: do a thing", "user": {"login": "someone"}}


def test_review_view_shows_a_warning(capsys):
    warn = cp.Finding(rule="subject-too-long", severity="warning",
                      message="Subject is 82 characters; keep it short.",
                      commit="abc123def456",
                      subject="ci: do a thing")
    cp.render_cli_review("qualcomm-linux", "meta-qcom", 2346, _meta(), [warn])
    out = capsys.readouterr().out
    assert "COMMENT" in out                       # verdict for warning-only
    assert "subject-too-long" in out              # the warning is rendered
    assert "1 warning" in out


def test_review_view_shows_an_error(capsys):
    err = cp.Finding(rule="kernel-prefix", severity="error",
                     message="Drop the kernel-tree prefix.",
                     commit="abc123def456", subject="FROMLIST: x")
    cp.render_cli_review("qualcomm-linux", "meta-qcom", 5, _meta(), [err])
    out = capsys.readouterr().out
    assert "REQUEST CHANGES" in out
    assert "kernel-prefix" in out


# --------------------------------------------------------------------------
# At-a-glance tags.
# --------------------------------------------------------------------------

def test_pr_tag_labels():
    err = cp.Finding(rule="x", severity="error", message="m")
    warn = cp.Finding(rule="y", severity="warning", message="m")
    assert "[ok]" in cp._pr_tag("ok", [])
    assert "[warn 1]" in cp._pr_tag("ok", [warn])
    assert "[err 2]" in cp._pr_tag("ok", [err, err])
    assert "[err 1]" in cp._pr_tag("ok", [err, warn])   # error wins over warn
    assert "[?]" in cp._pr_tag("err", None)             # could not check


def test_pr_tag_excludes_already_raised():
    # The bug: a warning a reviewer already raised still showed as [warn].
    warn = cp.Finding(rule="subject-too-long", severity="warning",
                      message="Subject is too long")
    assert "[warn 1]" in cp._pr_tag("ok", [warn], "")          # not yet raised
    assert "[ok]" in cp._pr_tag("ok", [warn], "the subject is too long")
    # an error already raised likewise drops to [ok]
    err = cp.Finding(rule="signoff-missing", severity="error", message="m")
    assert "[err 1]" in cp._pr_tag("ok", [err], "")
    assert "[ok]" in cp._pr_tag("ok", [err], "please add a signed-off-by")


# --------------------------------------------------------------------------
# Clickable URLs (OSC 8 hyperlinks).
# --------------------------------------------------------------------------

class _FakeTTY:
    def __init__(self, tty):
        self._tty = tty

    def isatty(self):
        return self._tty


def test_link_emits_osc8_on_a_tty(monkeypatch):
    monkeypatch.setattr(cp.sys, "stdout", _FakeTTY(True))
    monkeypatch.delenv("NO_HYPERLINKS", raising=False)
    link = cp._link("https://github.com/o/r/pull/5", "click")
    assert link == "\x1b]8;;https://github.com/o/r/pull/5\x1b\\click\x1b]8;;\x1b\\"


def test_link_defaults_label_to_url(monkeypatch):
    monkeypatch.setattr(cp.sys, "stdout", _FakeTTY(True))
    monkeypatch.delenv("NO_HYPERLINKS", raising=False)
    assert "https://x/y" in cp._link("https://x/y")


def test_link_plain_when_not_a_tty(monkeypatch):
    monkeypatch.setattr(cp.sys, "stdout", _FakeTTY(False))
    assert cp._link("https://x/y", "label") == "label"


def test_link_disabled_by_env(monkeypatch):
    monkeypatch.setattr(cp.sys, "stdout", _FakeTTY(True))
    monkeypatch.setenv("NO_HYPERLINKS", "1")
    assert cp._link("https://x/y", "label") == "label"


# --------------------------------------------------------------------------
# URL building.
# --------------------------------------------------------------------------

def test_comment_url_patch_file_anchors_the_diff_line():
    import hashlib
    f = cp.Finding(rule="patch-upstream-status", severity="error", message="m",
                   path="recipes-a/b.patch", line=3)
    url = cp.comment_url("o", "r", 5, f)
    h = hashlib.sha256(b"recipes-a/b.patch").hexdigest()
    assert url == f"https://github.com/o/r/pull/5/files#diff-{h}R3"


def test_comment_url_commit_finding():
    f = cp.Finding(rule="kernel-prefix", severity="error", message="m",
                   commit="abc123def456")
    assert cp.comment_url("o", "r", 5, f) == \
        "https://github.com/o/r/pull/5/commits/abc123def456"


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/qualcomm-linux/meta-qcom/pulls",
     ("qualcomm-linux", "meta-qcom", None)),
    ("https://github.com/qualcomm-linux/meta-qcom/pull/2348",
     ("qualcomm-linux", "meta-qcom", 2348)),
    ("https://github.com/qualcomm-linux/meta-qcom",
     ("qualcomm-linux", "meta-qcom", None)),
    ("https://github.com/o/r/pull/12/files",
     ("o", "r", 12)),
])
def test_parse_pr_url(url, expected):
    assert cp.parse_pr_url(url) == expected


def test_parse_pr_url_rejects_non_github():
    with pytest.raises(ValueError):
        cp.parse_pr_url("https://example.com/foo/bar")


# --------------------------------------------------------------------------
# Hiding findings that reviewers already raised.
# --------------------------------------------------------------------------

def test_already_raised_matches_rule_keywords():
    f_sob = cp.Finding(rule="signoff-missing", severity="error", message="m")
    f_kern = cp.Finding(rule="kernel-prefix", severity="error", message="m")
    text = "please add a signed-off-by line before we can merge"
    assert cp.already_raised(f_sob, text) is True
    assert cp.already_raised(f_kern, text) is False


def test_partition_already_raised():
    f_sob = cp.Finding(rule="signoff-missing", severity="error", message="m",
                       commit="a")
    f_kern = cp.Finding(rule="kernel-prefix", severity="error", message="m",
                        commit="a")
    new, raised = cp.partition_already_raised(
        [f_kern, f_sob], "you forgot the sign-off")
    assert [f.rule for f in new] == ["kernel-prefix"]
    assert [f.rule for f in raised] == ["signoff-missing"]


def test_partition_no_discussion_keeps_all():
    f = cp.Finding(rule="signoff-missing", severity="error", message="m")
    new, raised = cp.partition_already_raised([f], "")
    assert new == [f] and raised == []


def test_render_hides_already_raised(capsys):
    raised_f = cp.Finding(rule="signoff-missing", severity="error",
                          message="Missing sign-off trailer", commit="abc123",
                          subject="x: y")
    new_f = cp.Finding(rule="kernel-prefix", severity="error",
                       message="Drop the FROMLIST prefix", commit="abc123",
                       subject="x: y")
    disc = "reviewer said: please add your signed-off-by"
    cp.render_cli_review("o", "r", 5, _meta(), [raised_f, new_f], disc)
    out = capsys.readouterr().out
    assert "kernel-prefix" in out                          # new finding shown
    assert "1 already raised by reviewers" in out          # verdict note
    assert "Already raised by reviewers (hidden): signoff-missing" in out
    assert "Missing sign-off trailer" not in out           # raised text hidden


def test_render_all_raised(capsys):
    f = cp.Finding(rule="signoff-missing", severity="error", message="m",
                   commit="abc123", subject="x: y")
    cp.render_cli_review("o", "r", 5, _meta(), [f],
                         "please add a sign-off")
    out = capsys.readouterr().out
    assert "nothing new to add" in out


def test_drop_drafts():
    items = [
        {"number": 1, "draft": False},
        {"number": 2, "draft": True},
        {"number": 3},                 # absent flag = not a draft
        {"number": 4, "draft": True},
    ]
    assert [it["number"] for it in cp._drop_drafts(items)] == [1, 3]
