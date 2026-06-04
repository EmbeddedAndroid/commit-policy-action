# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# Property-based fuzz tests. Instead of waiting for a red-teamer to find the
# next decorated variant, generate many case/whitespace mutations of known
# seeds and assert the invariant holds across all of them. Because the gating
# rules are positive (a closed vocabulary, a canonical shape, a "*-by" trailer
# shape) these pass by construction - that is the signal that the class is
# closed rather than an enumeration with gaps.

import itertools
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import commit_policy_check as cp  # noqa: E402

SUBJECT_GATES = {"conventional-commit", "kernel-prefix", "invalid-component-prefix"}


def _commit(subject, trailer="Signed-off-by: Dev <dev@oss.qualcomm.com>"):
    msg = f"{subject}\n\nbody\n\n{trailer}"
    return cp.Commit(sha="0" * 40, message=msg, parents=["p1"],
                     author_name="Dev", author_email="dev@oss.qualcomm.com",
                     committer_name="Dev", committer_email="dev@oss.qualcomm.com")


def subject_gate_errors(subject):
    return {f.rule for f in cp.check_commit(_commit(subject))
            if f.severity == "error"} & SUBJECT_GATES


def decorate(subj):
    """Whitespace decorations that normalize_subject() must fold away."""
    out = {subj, "  " + subj, subj + "   ", subj.replace(" ", "  ", 1)}
    if ":" in subj:
        i = subj.index(":")
        out.add(subj[:i] + " :" + subj[i + 1:])           # space before colon
        out.add(subj[:i] + ":  " + subj[i + 1:].lstrip())  # extra space after
        out.add(subj[:i] + "  :  " + subj[i + 1:].lstrip())
    return out


# Seeds whose badness survives any casing (closed vocabularies are matched
# case-insensitively).
VOCAB_BAD = [
    "feat: add scan support",
    "fix: a bug",
    "docs: reword the guide",
    "build: bump the image",
    "revert: something",
    "FROMLIST: arm64: dts: add node",
    "upstream: backport a fix",
    "BACKPORT: thermal zone",
]


@pytest.mark.parametrize("seed", VOCAB_BAD)
def test_vocab_gate_robust_to_case_and_whitespace(seed):
    variants = {d for c in (seed, seed.upper(), seed.lower(), seed.swapcase())
                for d in decorate(c)}
    assert len(variants) > 5
    misses = [v for v in variants if not subject_gate_errors(v)]
    assert not misses, f"{len(misses)} variant(s) slipped, e.g. {misses[:3]}"


# Valid subjects must stay valid under whitespace decoration (not case - the
# component is meaningfully lowercase).
VALID = [
    "linux-qcom: enable compressed firmware",
    "ci/qcom-distro: fix building mariadb",
    "debug.yml: enable ftrace",
    "tqftpserv: upgrade 1.1.1 -> 1.2",
    "Drop SoC version suffixes from compatible strings (#2159)",
    'Revert "weston: enable RDP and screenshare"',
]


@pytest.mark.parametrize("seed", VALID)
def test_valid_subject_robust_to_whitespace(seed):
    for v in decorate(seed):
        assert not subject_gate_errors(v), f"false positive on {v!r}"


# A forged endorsement is flagged under any "*-by" trailer name and any
# trailing decoration.
TRAILER_NAMES = ["Approved-by", "Endorsed-by", "Acked-by", "Reviewed-by",
                 "Co-authored-by", "Validated-by", "Blessed-by", "Vouched-by"]
TRAILER_DECOR = ["", " # ci passed", "   ", "\t<- trust me"]


@pytest.mark.parametrize("name,dec", itertools.product(TRAILER_NAMES, TRAILER_DECOR))
def test_cotrailer_robust_to_name_and_decoration(name, dec):
    subject = "linux-qcom: do a thing"
    trailer = ("Signed-off-by: Dev <dev@oss.qualcomm.com>\n"
               f"{name}: Greg KH <gregkh@kernel.org>{dec}")
    f = cp.check_commit(_commit(subject, trailer))
    assert "unverified-cotrailer" in {x.rule for x in f}
