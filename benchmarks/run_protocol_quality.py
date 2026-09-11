from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from protocol_validation import build_validation_plan, correlate_execution_evidence, validate_plan, STATUS


def finding(fid, category="state_machine", **extra):
    base = {"id": fid, "title": "Protocol candidate", "category": category, "contract": "Protocol", "function": "act"}
    base.update(extra)
    return base


def path(reachable=True, economic=None):
    value = {
        "entry_point": "Protocol.act",
        "reachable": reachable,
        "preconditions": ["attacker controls a test account", "required protocol state is established"],
        "sequence": [
            {"step": 1, "actor": "attacker", "action": "establish required initial state"},
            {"step": 2, "actor": "attacker", "action": "perform prerequisite state transition"},
            {"step": 3, "actor": "attacker", "action": "invoke Protocol.act"},
            {"step": 4, "actor": "observer", "action": "evaluate invariant and affected state"},
        ],
    }
    if economic is not None:
        value["economic_consequence"] = economic
    return value


def run():
    cases = [
        ("multi_step_exploitable", True, True, path(True), finding("multi_step", "state_machine")),
        ("unreachable", False, False, path(False), finding("unreachable", "state_machine")),
        ("authorization_dependent", True, True, path(True), finding("auth", "privilege", privileged=True)),
        ("invariant_preserving", False, False, path(True), finding("safe", "accounting", security_invariant="total accounting remains conserved")),
        ("economic_state_dependent", True, True, path(True, {"status": "quantified", "amount_usd": 1250, "basis": "local fixture balances"}), finding("economic", "accounting", economic_analysis={"status": "quantified", "amount_usd": 1250})),
    ]
    records = []
    for name, expected_reachable, expected_violation, p, f in cases:
        plan = build_validation_plan(f, {"functions": [{"contract": "Protocol", "name": "act", "file": "Protocol.sol", "line": 1}]}, [p])
        errors = validate_plan(plan)
        observed_reachable = plan["reachability_constraints"]["status"] == "mapped" and p.get("reachable") is not False
        records.append({"case": name, "expected_reachable": expected_reachable, "observed_reachable": observed_reachable, "expected_violation": expected_violation, "plan_valid": not errors, "errors": errors, "economic": plan["economic_consequence"]})

    same = {"engine": "forge", "finding_id": "f", "hypothesis_id": "h", "security_invariant": "I", "security_assertion": True, "invariant_result": "violated", "outcome": "reproduced", "returncode": 1, "stdout_sha256": "a", "stderr_sha256": "b"}
    repeated = correlate_execution_evidence([same, dict(same)])
    independent = correlate_execution_evidence([same, {**same, "engine": "halmos", "stdout_sha256": "c"}])
    unrelated = correlate_execution_evidence([same, {**same, "engine": "halmos", "finding_id": "other", "hypothesis_id": "other"}])
    conflict = correlate_execution_evidence([same, {**same, "engine": "halmos", "outcome": "not_reproduced", "invariant_result": "preserved"}])
    malformed = correlate_execution_evidence([same, {"engine": "halmos", "outcome": "reproduced"}])
    evidence = {
        "repeated_same_confidence": repeated["confidence_delta"] == correlate_execution_evidence([same])["confidence_delta"],
        "independent_increases": independent["confidence_delta"] > repeated["confidence_delta"],
        "unrelated_does_not_increase": unrelated["confidence_delta"] == repeated["confidence_delta"],
        "conflict_reduces": conflict["confidence_delta"] < independent["confidence_delta"],
        "malformed_penalized": malformed["malformed_evidence_count"] == 1 and malformed["confidence_delta"] < repeated["confidence_delta"],
    }
    quality = {
        "reachability_correct": sum(r["observed_reachable"] == r["expected_reachable"] for r in records) / len(records),
        "plan_validity": sum(r["plan_valid"] for r in records) / len(records),
        "expected_violation_cases_represented": sum((r["expected_violation"] and r["plan_valid"]) or (not r["expected_violation"]) for r in records) / len(records),
        "evidence_consistency": sum(evidence.values()) / len(evidence),
        "economic_case_preserved": records[4]["economic"]["status"] == "quantified" and records[4]["economic"]["analysis"].get("amount_usd") == 1250,
    }
    # These are executable quality measurements over deterministic local cases, not production claims.
    quality["all_quality_assertions"] = all(evidence.values()) and quality["reachability_correct"] == 1.0 and quality["economic_case_preserved"]
    payload = {"benchmark": "protocol-validation-effectiveness", "version": 1, "status": STATUS, "cases": records, "evidence": evidence, "quality": quality}
    out = ROOT / "benchmarks/results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "protocol_quality.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if quality["all_quality_assertions"] else 1


if __name__ == "__main__":
    raise SystemExit(run())
