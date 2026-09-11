"""Structured protocol-aware validation plans built from existing research evidence.

This layer describes what a reproduction must establish; it does not execute a
live target and it never treats a callable function as an exploit by itself.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List

STATUS = "UNVERIFIED — HUMAN REVIEW REQUIRED"

REQUIRED_FIELDS = (
    "attacker_preconditions",
    "protocol_state",
    "state_transitions",
    "attack_sequence",
    "security_invariant",
    "expected_violation",
    "affected_state",
    "reachability_constraints",
)


def _stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def evidence_fingerprint(observation: Dict[str, Any]) -> str:
    """Fingerprint substantive evidence, excluding nondeterministic timing fields."""
    execution = observation.get("execution") or observation
    material = {
        "engine": observation.get("engine") or execution.get("engine"),
        "finding_id": observation.get("finding_id") or execution.get("finding_id"),
        "command": execution.get("command"),
        "returncode": execution.get("returncode"),
        "stdout_sha256": execution.get("stdout_sha256"),
        "stderr_sha256": execution.get("stderr_sha256"),
        "trace": observation.get("trace") or observation.get("traces"),
        "coverage": observation.get("coverage"),
        "security_assertion": observation.get("security_assertion"),
        "invariant_result": observation.get("invariant_result"),
    }
    return hashlib.sha256(_stable(material).encode()).hexdigest()


def _function_for_finding(finding: Dict[str, Any], protocol_map: Dict[str, Any]) -> Dict[str, Any] | None:
    target = str(finding.get("function") or "")
    contract = str(finding.get("contract") or "")
    location = str(finding.get("location") or "")
    for fn in protocol_map.get("functions", []) or []:
        if target and fn.get("name") == target and (not contract or fn.get("contract") == contract):
            return fn
        if location and location.startswith(str(fn.get("file"))) and int(finding.get("line") or 0) == int(fn.get("line") or 0):
            return fn
    return None


def _matching_path(finding: Dict[str, Any], attack_paths: Iterable[Dict[str, Any]]) -> Dict[str, Any] | None:
    contract = str(finding.get("contract") or "")
    function = str(finding.get("function") or "")
    wanted = f"{contract}.{function}" if contract and function else function
    for path in attack_paths or []:
        if wanted and path.get("entry_point") == wanted:
            return path
        if function and str(path.get("entry_point", "")).split(".")[-1] == function:
            return path
    return None


def build_validation_plan(
    finding: Dict[str, Any],
    protocol_map: Dict[str, Any] | None = None,
    attack_paths: Iterable[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Turn source-derived signals into an explicit, testable attack hypothesis."""
    protocol_map = protocol_map or {}
    fn = _function_for_finding(finding, protocol_map)
    path = _matching_path(finding, attack_paths or finding.get("attack_paths", []))
    category = str(finding.get("category") or "unknown").lower()
    title = str(finding.get("title") or "candidate")
    target = f"{fn.get('contract')}.{fn.get('name')}" if fn else str(finding.get("function") or "unknown entry point")
    risk_signals = list((path or {}).get("risk_signals", []))
    if fn:
        if fn.get("value_flow") and "asset movement" not in risk_signals: risk_signals.append("asset movement")
        if fn.get("oracle_dependency") and "oracle input" not in risk_signals: risk_signals.append("oracle input")
        if fn.get("external_call") and "external callback" not in risk_signals: risk_signals.append("external callback")
        if fn.get("state_write") and "state transition" not in risk_signals: risk_signals.append("state transition")
        if fn.get("privileged") and "privileged boundary" not in risk_signals: risk_signals.append("privileged boundary")

    invariant_map = {
        "accounting": "protocol value and accounting quantities remain conserved across the ordered state transition",
        "asset_flow": "assets can only move to an allowed recipient/amount under the protocol's authorization and accounting rules",
        "external_call": "external calls cannot cause an unauthorized state/value transition before required state updates",
        "oracle": "state-changing decisions use an authorized, sufficiently fresh and correctly normalized oracle value",
        "privilege": "only an authorized role can perform the privileged state or asset transition",
        "state_machine": "every state transition satisfies the protocol's required predecessor and authorization conditions",
        "upgrade": "implementation/initialization transitions remain authorized and storage invariants remain valid",
        "precision": "rounding and unit conversions do not create unauthorized value or accounting drift",
    }
    invariant = str(finding.get("security_invariant") or invariant_map.get(category) or "the stated security property remains true after the complete attack sequence")
    preconditions = list((path or {}).get("preconditions", [])) or ["attacker can reach the identified entry point within the authorized local/test scope"]
    state = {
        "entry_function": target,
        "before": "record relevant balances, roles, oracle values, state variables and protocol configuration",
        "during": risk_signals,
        "after": "record affected balances, roles, state variables and externally observable protocol state",
    }
    sequence = list((path or {}).get("sequence", []))
    if not sequence:
        sequence = [
            {"step": 1, "actor": "attacker", "action": "establish attacker preconditions and initial state"},
            {"step": 2, "actor": "attacker", "action": f"invoke {target} using only in-scope test inputs"},
            {"step": 3, "actor": "protocol", "action": "apply the relevant state transitions and external calls"},
            {"step": 4, "actor": "observer", "action": "evaluate the security invariant against post-state and trace"},
        ]
    expected = str(finding.get("expected_violation") or f"{invariant} is false after the ordered sequence")
    affected = finding.get("affected_asset") or finding.get("affected_state") or finding.get("asset") or "affected protocol state/value flow not yet quantified"
    reachability = {
        "entry_point": target,
        "source_mapped": bool(fn),
        "path_mapped": bool(path),
        "requires_authorized_local_execution": True,
        "live_target_allowed": False,
    }
    economics = finding.get("economic_analysis") or {}
    economic_consequence = {
        "status": "unquantified",
        "analysis": economics,
        "requirement": "quantify only from source-derived balances/prices/fees or reproduced local evidence; never infer from scanner severity",
    }
    return {
        "finding_id": finding.get("id"),
        "title": title,
        "attacker_preconditions": preconditions,
        "protocol_state": state,
        "state_transitions": [s.get("action", s) if isinstance(s, dict) else s for s in sequence],
        "attack_sequence": sequence,
        "security_invariant": invariant,
        "expected_violation": expected,
        "affected_state": affected,
        "reachability_constraints": reachability,
        "economic_consequence": economic_consequence,
        "risk_signals": risk_signals,
        "protocol_mapping": {"function": fn, "attack_path": path},
        "status": STATUS,
        "validation_only": True,
    }


def validate_plan(plan: Dict[str, Any]) -> List[str]:
    errors = [k for k in REQUIRED_FIELDS if not plan.get(k)]
    seq = plan.get("attack_sequence")
    if not isinstance(seq, list) or len(seq) < 2: errors.append("attack_sequence")
    reach = plan.get("reachability_constraints")
    if not isinstance(reach, dict) or not reach.get("requires_authorized_local_execution"): errors.append("authorization")
    if isinstance(reach, dict) and reach.get("live_target_allowed") is True: errors.append("live_target_policy")
    return errors


def correlate_execution_evidence(observations: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Combine only relevant independent evidence; duplicate output never adds confidence."""
    obs = [dict(o) for o in observations]
    fingerprints = [evidence_fingerprint(o) for o in obs]
    unique = list(dict.fromkeys(fingerprints))
    engines = {str(o.get("engine") or (o.get("execution") or {}).get("engine") or "unknown") for o in obs}
    substantive = [o for o in obs if o.get("security_assertion") or o.get("invariant_result") or o.get("vulnerability_reproduced")]
    independent = len({e for e in engines if e != "unknown"})
    conflicting = len({str(o.get("outcome") or o.get("status") or "unknown") for o in obs}) > 1
    score = 0.0
    if substantive: score += 0.35
    score += min(0.35, max(0, independent - 1) * 0.175)
    if len(substantive) >= 2 and len(unique) >= 2: score += 0.20
    if conflicting: score -= 0.15
    return {
        "observations": obs,
        "unique_evidence_fingerprints": unique,
        "independent_engines": sorted(engines),
        "independent_engine_count": independent,
        "conflicting": conflicting,
        "substantive_evidence_count": len(substantive),
        "confidence_delta": round(max(0.0, min(0.9, score)), 3),
        "repeatable": len(obs) >= 2 and len(unique) == 1,
        "review_status": STATUS,
    }
