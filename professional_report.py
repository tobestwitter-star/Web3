"""Evidence-grounded professional bounty reports for the authorized research pipeline."""
from __future__ import annotations
from typing import Any, Dict, Iterable, List
STATUS = "UNVERIFIED — HUMAN REVIEW REQUIRED"
DUPLICATE = "POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED"

def _list(value: Any) -> List[Any]:
    if value is None:return []
    return value if isinstance(value, list) else [value]
def _first(mapping: Dict[str, Any], *keys: str, default=None):
    for key in keys:
        value=mapping.get(key)
        if value not in (None,"",[]):return value
    return default
def _registry_for(finding: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    registry=analysis.get("evidence_registry") or {};value=registry.get(str(finding.get("id")),registry.get(finding.get("id"),{}))
    return value if isinstance(value,dict) else {}
def _structured_engine_evidence(finding: Dict[str, Any], registry: Dict[str, Any]) -> List[Dict[str, Any]]:
    observations=registry.get("engine_observations")
    if isinstance(observations,list) and observations:return observations
    observations=finding.get("engine_observations")
    return observations if isinstance(observations,list) else []
def _conflicts(registry: Dict[str, Any]) -> List[Dict[str, Any]]:
    conflicts=registry.get("conflicts")
    return conflicts if isinstance(conflicts,list) else []

def build_professional_report(findings: Iterable[Dict[str, Any]], opportunity: Dict[str, Any] | None = None, analysis: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Build a report from final correlated findings and authoritative structured evidence."""
    opp=opportunity or {};analysis=analysis or {};scope=analysis.get("scope") or opp.get("scope_evidence") or opp.get("scope_notes")
    authorization=analysis.get("authorization") or {"required":True,"confirmed":bool(analysis.get("authorization_confirmed")),"evidence":scope};reports=[]
    for f in findings or []:
        registry=_registry_for(f,analysis);historical=f.get("historical_intelligence") or {};matches=historical.get("matches") or f.get("possible_duplicate_indicators") or []
        duplicate_status=f.get("duplicate_classification")
        if not duplicate_status or duplicate_status=="no useful match":duplicate_status=DUPLICATE if matches else "no historical match established"
        raw_reproduction=registry.get("reproduction")
        if raw_reproduction is None:raw_reproduction=f.get("execution_evidence")
        if raw_reproduction is None:raw_reproduction={}
        reproduction=dict(raw_reproduction) if isinstance(raw_reproduction,dict) else {"malformed":raw_reproduction}
        if not reproduction:reproduction={"evidence":None,"status":"not demonstrated","reproducibility_score":f.get("reproducibility")}
        else:
            reproduction.setdefault("evidence",f.get("execution_evidence"));reproduction.setdefault("reproducibility_score",f.get("reproducibility"));reproduction.setdefault("status","observed execution evidence" if f.get("execution_evidence") else "not demonstrated")
        reports.append({
            "finding_id":f.get("id"),"title":_first(f,"title","vulnerability","check",default="Potential vulnerability"),"severity":_first(f,"severity",default="unrated"),
            "vulnerability_summary":_first(f,"summary","description",default=None),"affected_protocol":_first(f,"protocol",default=opp.get("name")),"affected_contract":_first(f,"contract",default=None),"affected_contracts":_list(f.get("contracts") or f.get("affected_contracts")),
            "affected_function":_first(f,"function",default=None),"affected_functions":_list(f.get("functions") or f.get("affected_functions")),"source_locations":_list(f.get("location") or f.get("source_locations") or f.get("file")),
            "attack_path":_list(f.get("attack_paths") or f.get("attack_path")),"attack_path_uncertain":f.get("attack_path_uncertain"),"protocol_validation_plan":registry.get("protocol_validation_plan") or f.get("validation_plan"),
            "root_cause":f.get("root_cause"),"exploitability_reasoning":_first(f,"exploitability_reasoning","exploitability","attack_scenario"),"reproduction":reproduction,"engine_evidence":_structured_engine_evidence(f,registry),
            "engine_provenance":registry.get("engine_provenance") or f.get("engines") or _list(f.get("engine")),"execution_metadata":registry.get("execution_metadata") or [],
            "traces_inputs_coverage_symbolic":{"trace":registry.get("trace",f.get("trace")),"inputs":registry.get("inputs",f.get("inputs")),"coverage":registry.get("coverage",f.get("coverage")),"symbolic":registry.get("symbolic",f.get("symbolic_evidence")),"invariants":registry.get("invariant",f.get("invariant_evidence"))},
            "conflicting_evidence":_conflicts(registry),"economic_impact":registry.get("economic_analysis") or f.get("economic_analysis") or f.get("economic_impact"),"scope_evidence":f.get("scope_evidence") or scope,"authorization_evidence":authorization,"historical_context":f.get("historical_context") or [],
            "exact_historical_fingerprint_matches":[m for m in matches if isinstance(m,dict) and m.get("match_type")=="exact_normalized_fingerprint"],"semantic_similarity_leads":[m for m in matches if isinstance(m,dict) and m.get("match_type")=="semantic_similarity_lead"],"duplicate_status":duplicate_status,
            "confidence":f.get("cross_tool_confidence",f.get("confidence")),"validated_by_multiple_tools":f.get("validated_by_multiple_tools"),"limitations":_list(f.get("limitations") or ["Finding remains unverified and requires independent human reproduction."]),"remediation":f.get("remediation"),"evidence_provenance":registry.get("provenance") or _list(f.get("evidence_provenance") or f.get("source_attribution")),"review_status":STATUS,
        })
    return {"report_version":"1.1","report_type":"professional_bounty_report","review_status":STATUS,"do_not_auto_submit":True,"human_review_only":True,"observed_facts_vs_analysis":"Evidence fields are observations from recorded engine executions; reasoning fields are analysis and remain subject to human verification.","opportunity":{k:opp.get(k) for k in ("id","name","source","url","max_bounty_usd","score")},"scope_and_authorization":{"scope":scope,"authorization":authorization},"findings":reports,"submission":{"automatic_submission":False,"manual_submission_allowed_only_after_human_approval":True},"limitations":["Missing evidence is not inferred or fabricated.","Conflicting or partial engine evidence is preserved for human review.","UNVERIFIED findings require human reproduction and scope verification.","Historical similarity is not proof of duplication."]}
