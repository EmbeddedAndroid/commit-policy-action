# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# Corpus ground-truth gate. Runs the checker over the labelled corpus and
# asserts the gate decision is perfect on it: no compliant commit is blocked
# (precision) and no labelled offender slips through (recall). This is the
# regression ratchet for the gate as a whole, not just per-fixture.

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import corpus_eval  # noqa: E402


def test_corpus_gate_is_perfect():
    cases = corpus_eval.load()
    assert len(cases) >= 20, "corpus too small to be meaningful"
    m = corpus_eval.evaluate(cases)
    assert m["fp"] == 0, f"compliant commits were gated: {m['misclassified']}"
    assert m["fn"] == 0, f"offenders slipped the gate: {m['misclassified']}"
    assert m["precision"] == 1.0 and m["recall"] == 1.0


def test_corpus_has_both_classes():
    # A precision/recall number is only meaningful with positives and
    # negatives, including the semantic-limit cases that must NOT gate.
    cases = corpus_eval.load()
    assert sum(c["expected_gate"] for c in cases) >= 8
    assert sum(not c["expected_gate"] for c in cases) >= 8
