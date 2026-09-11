"""Evidence-grounded professional bounty reports for the authorized research pipeline."""
from __future__ import annotations
from typing import Any, Dict, Iterable, List

STATUS = "UNVERIFIED — HUMAN REVIEW REQUIRED"
DUPLICATE = "POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED"


def _list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first(mapping: Dict[str, Any], *keys: str, default=None):
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", []):
            return value
    return default


def _engine_evidence(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    observations = finding.get("engine_observations") or []
    if observations:
        return observations
    evidence = finding.get("evidence") or []
    engines = finding.get("engines") or ([finding.get("engine")] if finding.get("engine") else [])
    return [{"engine": engine, "evidence": evidence} for engine in engines]


def build_professional_report(findings: Iterable[Dict[str, Any]], opportunity: Dict[str, Any] | None = None, analysis: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Build the final report from correlated/enriched pipeline findings only.

    Missing evidence stays missing. The report never upgrades an observation to a
    proven finding and never performs or implies bounty submission.
    """
    opp = opportunity or {}
    analysis = analysis or {}
    scope = analysis.get("scope") or opp.get("scope_evidence") or opp.get("scope_notes")
    authorization = analysis.get("authorization") or {
        "required": True,
        "confirmed": bool(analysis.get("authorization_confirmed")),
        "evidence": scope,
    }
    reports: List[Dict[str, Any]] = []
    for f in findings or []:
        historical = f.get("historical_intelligence") or {}
        matches = historical.get("matches") or f.get("possible_duplicate_indicators") or []
        duplicate_status = f.get("duplicate_classification")
        if not duplicate_status or duplicate_status == "no useful match":
            duplicate_status = DUPLICATE if matches else "no historical match established"
        reports.append({
            "finding_id": f.get("id"),
            "title": _first(f, "title", "vulnerability", "check", default="Potential vulnerability"),
            "severity": _first(f, "severity", default="unrated"),
            "vulnerability_summary": _first(f, "summary", "description", default=None),
            "affected_protocol": _first(f, "protocol", default=opp.get("name")),
            "affected_contract": _first(f, "contract", default=None),
            "affected_contracts": _list(f.get("contracts") or f.get("affected_contracts")),
            "affected_function": _first(f, "function", default=None),
            "affected_functions": _list(f.get("functions") or f.get("affected_functions")),
            "source_locations": _list(f.get("location") or f.get("source_locations") or f.get("file")),
            "attack_path": _list(f.get("attack_paths") or f.get("attack_path")),
            "attack_path_uncertain": f.get("attack_path_uncertain"),
            "root_cause": f.get("root_cause"),
            "exploitability_reasoning": _first(f, "exploitability_reasoning", "exploitability", "attack_scenario"),
            "reproduction": {
                "evidence": f.get("execution_evidence"),
                "reproducibility_score": f.get("reproducibility"),
                "status": "observed execution evidence" if f.get("execution_evidence") else "not demonstrated",
            },
            "engine_evidence": _engine_evidence(f),
            "engine_provenance": _list(f.get("engines") or f.get("engine")),
            "traces_inputs_coverage_symbolic": {
                "trace": f.get("trace"),
                "inputs": f.get("inputs"),
                "coverage": f.get("coverage"),
                "symbolic": f.get("symbolic_evidence"),
                "invariants": f.get("invariant_evidence"),
            },
            "economic_impact": f.get("economic_analysis") or f.get("economic_impact"),
            "scope_evidence": f.get("scope_evidence") or scope,
            "authorization_evidence": authorization,
            "historical_context": f.get("historical_context") or [],
            "exact_historical_fingerprint_matches": [m for m in matches if isinstance(m, dict) and m.get("match_type") == "exact_normalized_fingerprint"],
            "semantic_similarity_leads": [m for m in matches if isinstance(m, dict) and m.get("match_type") == "semantic_similarity_lead"],
            "duplicate_status": duplicate_status,
            "confidence": f.get("cross_tool_confidence", f.get("confidence")),
            "validated_by_multiple_tools": f.get("validated_by_multiple_tools"),
            "limitations": _list(f.get("limitations") or ["Finding remains unverified and requires independent human reproduction."]),
            "remediation": f.get("remediation"),
            "evidence_provenance": _list(f.get("evidence_provenance") or f.get("source_attribution")),
            "review_status": STATUS,
        })
    return {
        "report_version": "1.0",
        "report_type": "professional_bounty_report",
        "review_status": STATUS,
        "do_not_auto_submit": True,
        "human_review_only": True,
        "observed_facts_vs_analysis": "Evidence fields are observations supplied by the pipeline; reasoning fields are analysis and remain subject to human verification.",
        "opportunity": {k: opp.get(k) for k in ("id", "name", "source", "url", "max_bounty_usd", "score")},
        "scope_and_authorization": {"scope": scope, "authorization": authorization},
        "findings": reports,
        "submission": {"automatic_submission": False, "manual_submission_allowed_only_after_human_approval": True},
        "limitations": ["Missing evidence is not inferred or fabricated.", "UNVERIFIED findings require human reproduction and scope verification.", "Historical similarity is not proof of duplication."],
    }
