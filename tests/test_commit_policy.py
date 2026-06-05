# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# Unit tests for commit_policy_check.py. Offending and compliant commits are
# real commits from meta-qcom pull requests (PR number noted on each), plus
# regression fixtures for the recorded evasion rounds.
#
# Run with: python3 -m pytest tests/ -q

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import commit_policy_check as cp  # noqa: E402


def commit(message, author=None, parents=None, committer=None,
           author_login="", committer_login=""):
    if author is None:
        sobs, _ = cp.parse_signoffs(message)
        name, email = sobs[-1] if sobs else ("Nobody", "nobody@example.com")
    else:
        name, email = author
    cname, cemail = committer if committer else (name, email)
    return cp.Commit(sha="0" * 40, message=message, parents=parents or ["p1"],
                     author_name=name, author_email=email,
                     committer_name=cname, committer_email=cemail,
                     author_login=author_login, committer_login=committer_login)


def rules(findings):
    return {f.rule for f in findings}


def errors(findings):
    return {f.rule for f in findings if f.severity == "error"}


# --------------------------------------------------------------------------
# Real offending commits (round-0 fixtures).
# --------------------------------------------------------------------------

def test_pr2031_malformed_signoff():
    msg = ("Add initial support for Bluetooth Channel Sounding using HCI\n\n"
           "Body.\n\n"
           "Signed-off-by: prathibhamadugonde<prathibha.madugonde@oss.qualcomm.com>")
    f = cp.check_commit(commit(msg, author=(
        "Prathibha Madugonde", "prathibha.madugonde@oss.qualcomm.com")))
    assert "signoff-malformed" in errors(f)
    assert "signoff-missing" not in errors(f)


def test_pr2189_webclient_identity():
    msg = ("sensors: upgrade iqx7181 registry files\n\n"
           "Signed-off-by: wayi-art <82081381+wayi-art@users.noreply.github.com>")
    f = cp.check_commit(commit(msg, author=(
        "wayi-art", "82081381+wayi-art@users.noreply.github.com")))
    assert "identity-webclient" in errors(f)


def test_pr1385_conventional_commit():
    msg = ("feat(tflite): add comprehensive GPU optimizations\n\nBody.\n\n"
           "Signed-off-by: Tushar Darote <tdarote@qti.qualcomm.com>")
    assert "conventional-commit" in errors(cp.check_commit(commit(msg)))


def test_pr1937_kernel_prefix():
    msg = ("FROMLIST: arm64: dts: qcom: lemans: Enable DISPLAY-PORT\n\nb\n\n"
           "Signed-off-by: Kumar Anurag <kumar.singh@oss.qualcomm.com>")
    assert "kernel-prefix" in errors(cp.check_commit(commit(msg)))


def test_pr1951_colon_space():
    msg = ("qwes:Migrate SRC_URI for prebuilts to QArtifactory\n\nb\n\n"
           "Signed-off-by: Mani Sankar Javvaji <mjavvaji@qti.qualcomm.com>")
    assert "invalid-component-prefix" in errors(cp.check_commit(commit(msg)))


def test_pr1889_missing_signoff():
    f = cp.check_commit(commit(
        "[fix issue 1888] by adding host checks\n\nBody without a sign-off.",
        author=("aprabhak", "aprabhak@qti.qualcomm.com")))
    assert "signoff-missing" in errors(f)


def test_pr1612_webedit_and_identity():
    msg = ("Create monitor-token-bucket.yml\n\nworkflow\n\n"
           "Signed-off-by: steve345 <7432003+steve345@users.noreply.github.com>")
    f = cp.check_commit(commit(msg, author=(
        "steve345", "7432003+steve345@users.noreply.github.com")))
    # web-edit subject is advisory now; the noreply identity is what gates.
    assert "webedit-subject" in rules(f)
    assert "identity-webclient" in errors(f)


def test_merge_commit_in_series():
    f = cp.check_commit(commit(
        "Merge branch 'master' into feature\n\n"
        "Signed-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com"), parents=["p1", "p2"]))
    assert "merge-commit" in errors(f)


def test_patch_missing_upstream_status():
    good = cp.PatchFile("a/good.patch", "Upstream-Status: Pending\n--- a\n+++ b\n")
    bad = cp.PatchFile("a/bad.patch", "From: a\nSubject: x\n--- a\n+++ b\n")
    f = cp.check_patch_files([good, bad])
    assert errors(f) == {"patch-upstream-status"}
    assert f[0].path == "a/bad.patch" and f[0].line == 1


GOOD = [
    ("linux-yocto-dev: enable loading of compressed firmware\n\n"
     "CI uses compressed firmware; enable the Kconfig options.\n\n"
     "Signed-off-by: Dmitry Baryshkov <dmitry.baryshkov@oss.qualcomm.com>"),
    ("ci/qcom-distro: fix building MariaDB for Glymur\n\n"
     "Assembler messages:\n{standard input}:169: Error: ...\n\n"
     "Signed-off-by: Dmitry Baryshkov <dmitry.baryshkov@oss.qualcomm.com>"),
    ("tqftpserv: upgrade 1.1.1 -> 1.2\n\nProtocol fixes.\n\n"
     "- fix: add path validation in tqftpserv.c\n\n"
     "Signed-off-by: Dmitry Baryshkov <dmitry.baryshkov@oss.qualcomm.com>"),
]


@pytest.mark.parametrize("msg", GOOD, ids=["pr2252", "pr2253", "pr2227"])
def test_compliant_commits_have_no_errors(msg):
    f = cp.check_commit(commit(msg, author=(
        "Dmitry Baryshkov", "dmitry.baryshkov@oss.qualcomm.com")))
    assert errors(f) == set(), [x.rule for x in f if x.severity == "error"]


# --------------------------------------------------------------------------
# Evasion round 1.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("subj", [
    "docs: reword the agent guide introduction",
    "build: bump the default kas-container image tag",
    'revert: "ci/qcom-distro: include meta-dpdk layer (#1902)"',
], ids=["docs", "build", "revert"])
def test_cc_unlisted_types(subj):
    f = cp.check_commit(commit(
        subj + "\n\nb\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "conventional-commit" in errors(f)


def test_ci_component_not_flagged():
    f = cp.check_commit(commit(
        "ci: base.lock: update meta-openembedded\n\nb\n\n"
        "Signed-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "conventional-commit" not in errors(f)
    assert "component-colon-space" not in errors(f)


@pytest.mark.parametrize("subj", [
    "Fromlist: add wcn6855 firmware nodes",
    "UPSTREAM : backport thermal zone fix",
    "fromlist: lower-case prefix",
], ids=["mixedcase", "space-before-colon", "lowercase"])
def test_kernel_prefix_evasion(subj):
    f = cp.check_commit(commit(
        subj + "\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "kernel-prefix" in errors(f)


def test_forged_cotrailers_warned_not_gated():
    msg = ("linux-qcom: enable demo node\n\nwhy\n\n"
           "Signed-off-by: Tyler Baker <tyler.baker@oss.qualcomm.com>\n"
           "Reviewed-by: Dmitry Baryshkov <dmitry.baryshkov@oss.qualcomm.com>\n"
           "Acked-by: Linus Torvalds <torvalds@linux-foundation.org>")
    f = cp.check_commit(commit(msg, author=(
        "Tyler Baker", "tyler.baker@oss.qualcomm.com")))
    assert "unverified-cotrailer" in rules(f)
    assert "unverified-cotrailer" not in errors(f)


def test_patch_bogus_upstream_status():
    f = cp.check_patch_files([cp.PatchFile(
        "a/z.patch", "Upstream-Status: Yes please, trust me\n--- a\n+++ b\n")])
    assert errors(f) == {"patch-upstream-status"}
    assert "Yes" in f[0].message


def test_patch_valid_upstream_status_with_detail():
    f = cp.check_patch_files([cp.PatchFile(
        "a/z.patch", "Upstream-Status: Backport [https://x/c/abc]\n--- a\n+++ b\n")])
    assert f == []


# --------------------------------------------------------------------------
# Evasion round 2.
# --------------------------------------------------------------------------

# #9: co-trailer rule must cover Co-authored-by / Reported-by / Suggested-by,
# and must not be escaped by a trailing comment after the address.
@pytest.mark.parametrize("trailer", [
    "Co-authored-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>",
    "Reported-by: Linus Torvalds <torvalds@linux-foundation.org>",
    "Suggested-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>",
    "Acked-by: Linus Torvalds <torvalds@linux-foundation.org> # looks legit",
], ids=["co-authored-by", "reported-by", "suggested-by", "trailing-comment"])
def test_cotrailer_evasion(trailer):
    msg = ("linux-qcom: do a thing\n\nwhy\n\n"
           "Signed-off-by: Dev <dev@oss.qualcomm.com>\n" + trailer)
    f = cp.check_commit(commit(msg, author=("Dev", "dev@oss.qualcomm.com")))
    assert "unverified-cotrailer" in rules(f)


def test_own_signoff_not_a_cotrailer():
    f = cp.check_commit(commit(
        "linux-qcom: do a thing\n\nwhy\n\n"
        "Signed-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "unverified-cotrailer" not in rules(f)


# #10: extensionless GitHub web-editor subjects.
@pytest.mark.parametrize("subj", [
    "Update Kconfig", "Create Dockerfile", "Update Makefile", "Delete README",
], ids=["kconfig", "dockerfile", "makefile", "readme"])
def test_webedit_extensionless(subj):
    f = cp.check_commit(commit(
        subj + "\n\nb\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "webedit-subject" in rules(f)      # advisory warning
    assert "webedit-subject" not in errors(f)  # not a gate


@pytest.mark.parametrize("subj", [
    "Update the kernel defconfig for qcm6490",  # multi-word, legitimate
    "linux-qcom: update toolchain",             # component prefix
], ids=["multiword", "component"])
def test_webedit_no_false_positive(subj):
    f = cp.check_commit(commit(
        subj + "\n\nb\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "webedit-subject" not in rules(f)


# #11: Conventional Commits scope with a space before the parenthesis.
@pytest.mark.parametrize("subj", [
    "feat (wifi): add scan support",
    "feat(wifi): add scan support",
    "fix !: urgent",
], ids=["spaced-scope", "scope", "bang"])
def test_cc_spacing_variants(subj):
    f = cp.check_commit(commit(
        subj + "\n\nb\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "conventional-commit" in errors(f)


# --------------------------------------------------------------------------
# Evasion round 3.
# --------------------------------------------------------------------------

# #12a: authoring as someone other than the PR submitter (verified login).
def test_identity_spoof_author_not_submitter():
    msg = ("qcom-distro: enable a feature\n\nwhy\n\n"
           "Signed-off-by: Bjorn Andersson <andersson@kernel.org>")
    c = commit(msg, author=("Bjorn Andersson", "andersson@kernel.org"),
               author_login="andersson")
    f = cp.check_commit(c, pr_author="EmbeddedAndroid")
    assert "author-not-submitter" in rules(f)
    assert "author-not-submitter" not in errors(f)  # warning, not a gate


def test_backport_cherry_pick_not_flagged():
    # A backport carries the original author; author != submitter is expected.
    msg = ("iq-8275-evk: add monaco-ac EVK DTB\n\nbody\n\n"
           "Signed-off-by: Nirmesh Kumar Singh <nirmesh.singh@oss.qualcomm.com>\n"
           "(cherry picked from commit 1748139163918774a64a571a7fc9a51009162f6d)")
    c = commit(msg, author=("Nirmesh Kumar Singh",
                            "nirmesh.singh@oss.qualcomm.com"),
               author_login="nkumarsi")
    assert "author-not-submitter" not in rules(
        cp.check_commit(c, pr_author="quic-yocto-ci"))


def test_carried_patch_committer_is_submitter_not_flagged():
    # The submitter committed someone else's patch and signed off (DCO-correct).
    msg = ("ci: Add iq-x7181-evk to LAVA test device lists\n\nbody\n\n"
           "Signed-off-by: Shoudi Li <shoudil@qti.qualcomm.com>\n"
           "Signed-off-by: Xueqian Nie <xueqnie@qti.qualcomm.com>")
    c = commit(msg, author=("Shoudi Li", "shoudil@qti.qualcomm.com"),
               author_login="shoudil",
               committer=("Xueqian Nie", "xueqnie@qti.qualcomm.com"),
               committer_login="xueqnie")
    f = cp.check_commit(c, pr_author="xueqnie")
    assert "author-not-submitter" not in rules(f)
    assert "unverified-cotrailer" not in rules(f)  # committer sign-off is fine


def test_identity_self_authored_not_flagged():
    msg = ("qcom-distro: enable a feature\n\nwhy\n\n"
           "Signed-off-by: Dev <dev@oss.qualcomm.com>")
    c = commit(msg, author=("Dev", "dev@oss.qualcomm.com"),
               author_login="EmbeddedAndroid")
    f = cp.check_commit(c, pr_author="EmbeddedAndroid")
    assert "author-not-submitter" not in rules(f)


def test_unlinked_email_does_not_warn():
    # An email mapping to no GitHub account (login "") must not be flagged,
    # to avoid noise on the common off-GitHub commit email case.
    msg = ("qcom-distro: enable a feature\n\nwhy\n\n"
           "Signed-off-by: Dev <dev@oss.qualcomm.com>")
    c = commit(msg, author=("Dev", "dev@oss.qualcomm.com"), author_login="")
    assert "author-not-submitter" not in rules(
        cp.check_commit(c, pr_author="EmbeddedAndroid"))


# #12b: a forged sign-off laundered through the committer field. The committer
# is only trusted when GitHub confirms it is the PR submitter.
def test_committer_launder_still_flagged():
    msg = ("linux-qcom: do a thing\n\nwhy\n\n"
           "Signed-off-by: Tyler Baker <tyler.baker@oss.qualcomm.com>\n"
           "Signed-off-by: Greg Kroah-Hartman <gregkh@kernel.org>")
    c = commit(msg, author=("Tyler Baker", "tyler.baker@oss.qualcomm.com"),
               committer=("Greg Kroah-Hartman", "gregkh@kernel.org"),
               author_login="tylerbaker", committer_login="")
    f = cp.check_commit(c, pr_author="tylerbaker")
    assert "unverified-cotrailer" in rules(f)
    note = [x for x in f if x.rule == "unverified-cotrailer"][0].message
    assert "gregkh@kernel.org" in note


# #13: forged endorsement under a non-standard "*-by" trailer.
@pytest.mark.parametrize("trailer", [
    "Approved-by: Bjorn Andersson <andersson@kernel.org>",
    "Endorsed-by: Greg Kroah-Hartman <gregkh@kernel.org>",
], ids=["approved-by", "endorsed-by"])
def test_nonstandard_trailer(trailer):
    msg = ("linux-qcom: do a thing\n\nwhy\n\n"
           "Signed-off-by: Dev <dev@oss.qualcomm.com>\n" + trailer)
    f = cp.check_commit(commit(msg, author=("Dev", "dev@oss.qualcomm.com")))
    assert "unverified-cotrailer" in rules(f)


# #14: web-editor subject on an extensionless file outside the known set.
@pytest.mark.parametrize("subj", [
    "Create Jenkinsfile", "Update Doxyfile", "Update BUILD", "Update WORKSPACE",
], ids=["jenkinsfile", "doxyfile", "build", "workspace"])
def test_webedit_known_files_outside_set(subj):
    f = cp.check_commit(commit(
        subj + "\n\nb\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "webedit-subject" in rules(f)       # advisory warning
    assert "webedit-subject" not in errors(f)


@pytest.mark.parametrize("subj", [
    "Update toolchain", "Create sysroot", "Update copyright",
], ids=["toolchain", "sysroot", "copyright"])
def test_webedit_lowercase_words_not_flagged(subj):
    f = cp.check_commit(commit(
        subj + "\n\nb\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "webedit-subject" not in rules(f)


# --------------------------------------------------------------------------
# Positive subject grammar (one check subsumes colon-space + capitalisation).
# --------------------------------------------------------------------------

@pytest.mark.parametrize("subj", [
    "Weston: enable RDP",        # capitalised component
    "qwes:Migrate prebuilts",    # missing space after colon
    "Note: temporary hack",      # capitalised label
    "FOO.BAR: do a thing",       # upper-case component
], ids=["capitalised", "no-space", "label", "upper"])
def test_invalid_component_prefix(subj):
    f = cp.check_commit(commit(
        subj + "\n\nb\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    assert "invalid-component-prefix" in errors(f)


@pytest.mark.parametrize("subj,token,fixed", [
    ("Camera: Create new recipe", "Camera", "camera: Create new recipe"),
    ("qwes:Migrate prebuilts", "qwes", "qwes: Migrate prebuilts"),
    ("FOO.BAR: do a thing", "FOO.BAR", "foo.bar: do a thing"),
], ids=["capitalised", "no-space", "upper"])
def test_invalid_component_prefix_message(subj, token, fixed):
    f = cp.check_commit(commit(
        subj + "\n\nb\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    msg = [x.message for x in f if x.rule == "invalid-component-prefix"][0]
    assert token in msg          # the component they actually used
    assert fixed in msg          # the corrected form to copy


@pytest.mark.parametrize("subj", [
    "linux-qcom: enable thing",          # canonical component
    "ci/qcom-distro: fix the build",     # component with a slash
    "debug.yml: enable ftrace",          # component with a dot
    "Drop SoC version suffixes (#2159)",  # bare imperative, no prefix
    'Revert "weston: enable RDP"',        # bare imperative whose summary has a colon
    "x86: enable the thing",             # short lowercase component
], ids=["canonical", "slash", "dot", "bare", "revert", "short"])
def test_valid_subjects_not_flagged(subj):
    f = cp.check_commit(commit(
        subj + "\n\nbody\n\nSigned-off-by: Dev <dev@oss.qualcomm.com>",
        author=("Dev", "dev@oss.qualcomm.com")))
    bad = {"conventional-commit", "kernel-prefix", "invalid-component-prefix"}
    assert bad.isdisjoint(errors(f)), errors(f)


# Structural: a failed patch-content fetch is surfaced, not silently skipped.
def test_patch_unfetched_is_warned():
    f = cp.check_patch_files([cp.PatchFile("a/x.patch", None)])
    assert rules(f) == {"patch-unfetched"}
    assert f[0].severity == "warning" and f[0].path == "a/x.patch"


# --------------------------------------------------------------------------
# Configuration.
# --------------------------------------------------------------------------

def test_config_cc_allow_components():
    cfg = cp.Config(cc_allow_components=frozenset({"perf"}))
    # perf is now an allowed component, fix is not.
    assert "conventional-commit" not in errors(cp.check_commit(commit(
        "perf: tune the scheduler\n\nb\n\nSigned-off-by: D <d@x.io>",
        author=("D", "d@x.io")), cfg))
    assert "conventional-commit" in errors(cp.check_commit(commit(
        "fix: a bug\n\nb\n\nSigned-off-by: D <d@x.io>",
        author=("D", "d@x.io")), cfg))


def test_config_disable_rules():
    cfg = cp.Config(disable_rules=frozenset({"kernel-prefix"}))
    f = cp.check_all([commit(
        "FROMLIST: x\n\nSigned-off-by: D <d@x.io>", author=("D", "d@x.io"))],
        cfg=cfg)
    assert "kernel-prefix" not in rules(f)


def test_config_patch_check_off():
    cfg = cp.Config(patch_check=False)
    f = cp.check_all([], [cp.PatchFile("a/x.patch", "no header\n")], cfg)
    assert f == []


def test_config_subject_max_length():
    cfg = cp.Config(subject_max_length=10)
    f = cp.check_commit(commit(
        "linux-qcom: a fairly long subject line here\n\n"
        "Signed-off-by: D <d@x.io>", author=("D", "d@x.io")), cfg)
    assert "subject-too-long" in rules(f)


# --------------------------------------------------------------------------
# Review payload shaping.
# --------------------------------------------------------------------------

def test_review_requests_changes_on_error():
    f = cp.check_commit(commit(
        "FROMLIST: x\n\nSigned-off-by: D <d@x.io>", author=("D", "d@x.io")))
    payload = cp.build_review(f)
    assert payload["event"] == "REQUEST_CHANGES"
    for junk in (":x:", ":warning:", "##", "**", "—"):
        assert junk not in payload["body"]


def test_review_comments_when_clean():
    payload = cp.build_review([])
    assert payload["event"] == "COMMENT"
    assert "no issues found" in payload["body"].lower()


def test_clean_pr_posts_nothing():
    # A clean PR must not post a "passed" review; it is just noise.
    assert cp.should_post_review([]) is False
    assert cp.should_post_review([], approve_on_pass=True) is True
    warn = cp.Finding(rule="body-empty", severity="warning", message="m")
    err = cp.Finding(rule="kernel-prefix", severity="error", message="m")
    assert cp.should_post_review([warn]) is True
    assert cp.should_post_review([err]) is True


def test_review_body_uses_custom_guidelines():
    assert "CONTRIBUTING.md" in cp.build_review([], guidelines="CONTRIBUTING.md")["body"]


def test_review_inline_comment_for_patch_file():
    f = cp.check_patch_files([cp.PatchFile("a/bad.patch", "no header\n")])
    payload = cp.build_review(f)
    assert payload["comments"][0]["path"] == "a/bad.patch"
    assert payload["comments"][0]["line"] == 1
