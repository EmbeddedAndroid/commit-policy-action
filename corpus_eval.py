#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
#
# Evaluate the checker against a labelled corpus of real commits and report
# precision/recall on the GATE decision (does the commit produce a blocking
# error?). This replaces "wait for the red-teamer" with a number: a change
# that makes a compliant commit gate (a false gate) or lets a real offender
# through (a miss) shows up as a precision/recall drop. As coverage is added
# the metric should hold while the rule set stays small - that is convergence.
#
# The corpus (corpus/labeled.json) is a seed; it is meant to grow, ideally
# with hand-labelled commits mined from the project's accepted/rejected PRs.

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commit_policy_check as cp  # noqa: E402

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "corpus", "labeled.json")


def load(path=CORPUS):
    with open(path) as fh:
        return json.load(fh)


def _commit(case):
    return cp.Commit(
        sha=case.get("sha", "0" * 40), message=case["message"],
        parents=case.get("parents", ["p1"]),
        author_name=case.get("author_name", ""),
        author_email=case.get("author_email", ""),
        committer_name=case.get("committer_name", case.get("author_name", "")),
        committer_email=case.get("committer_email", case.get("author_email", "")),
        author_login=case.get("author_login", ""),
        committer_login=case.get("committer_login", ""))


def evaluate(cases, cfg=None):
    cfg = cfg or cp.Config()
    tp = fp = fn = tn = 0
    misclassified = []
    for case in cases:
        findings = cp.check_commit(_commit(case), cfg, pr_author=case.get("pr_author"))
        gated = cp.has_errors(findings)
        expected = case["expected_gate"]
        gates = sorted({f.rule for f in findings if f.severity == "error"})
        if gated and expected:
            tp += 1
        elif gated and not expected:
            fp += 1
            misclassified.append((case["id"], "false-gate", gates))
        elif not gated and expected:
            fn += 1
            misclassified.append((case["id"], "missed", gates))
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return {"n": len(cases), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall,
            "misclassified": misclassified}


def main(argv=None):
    cases = load()
    m = evaluate(cases)
    print(f"corpus: {m['n']} cases  "
          f"(tp={m['tp']} fp={m['fp']} fn={m['fn']} tn={m['tn']})")
    print(f"gate precision: {m['precision']:.3f}   recall: {m['recall']:.3f}")
    for cid, kind, gates in m["misclassified"]:
        print(f"  {kind}: {cid}  gates={gates}")
    return 0 if (m["fp"] == 0 and m["fn"] == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
