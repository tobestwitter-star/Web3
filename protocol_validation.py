"""Structured protocol-aware validation plans built from existing research evidence."""
from __future__ import annotations
import hashlib, json
from typing import Any, Dict, Iterable, List
STATUS="UNVERIFIED — HUMAN REVIEW REQUIRED"
DUPLICATE_STATUS="POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED"
REQUIRED_FIELDS=("attacker_preconditions","protocol_state","state_transitions","attack_sequence","security_invariant","expected_violation","affected_state","reachability_constraints")

def _stable(value:Any)->str:return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,default=str)
def evidence_fingerprint(o:Dict[str,Any])->str:
 e=o.get("execution") or o
 m={"engine":o.get("engine") or e.get("engine"),"finding_id":o.get("finding_id") or e.get("finding_id"),"hypothesis_id":o.get("hypothesis_id"),"invariant":o.get("security_invariant"),"command":e.get("command"),"returncode":e.get("returncode"),"stdout_sha256":e.get("stdout_sha256"),"stderr_sha256":e.get("stderr_sha256"),"trace":o.get("trace") or o.get("traces"),"coverage":o.get("coverage"),"security_assertion":o.get("security_assertion"),"invariant_result":o.get("invariant_result")}
 return hashlib.sha256(_stable(m).encode()).hexdigest()

def _function_for_finding(f:Dict[str,Any],pm:Dict[str,Any])->Dict[str,Any]|None:
 target,contract,location=str(f.get("function") or ""),str(f.get("contract") or ""),str(f.get("location") or "")
 for fn in pm.get("functions",[]) or []:
  if target and fn.get("name")==target and (not contract or fn.get("contract")==contract):return fn
  if location and location.startswith(str(fn.get("file"))) and int(f.get("line") or 0)==int(fn.get("line") or 0):return fn
 return None

def _matching_path(f:Dict[str,Any],paths:Iterable[Dict[str,Any]])->Dict[str,Any]|None:
 contract,function=str(f.get("contract") or ""),str(f.get("function") or "");wanted=f"{contract}.{function}" if contract and function else function
 for p in paths or []:
  if wanted and p.get("entry_point")==wanted:return p
  if function and str(p.get("entry_point","")).split(".")[-1]==function:return p
 return None

def build_validation_plan(finding:Dict[str,Any],protocol_map:Dict[str,Any]|None=None,attack_paths:Iterable[Dict[str,Any]]|None=None)->Dict[str,Any]:
 pm=protocol_map or {};fn=_function_for_finding(finding,pm);path=_matching_path(finding,attack_paths or finding.get("attack_paths",[]));category=str(finding.get("category") or "unknown").lower();title=str(finding.get("title") or "candidate");target=f"{fn.get('contract')}.{fn.get('name')}" if fn else str(finding.get("function") or "unknown entry point")
 risks=list((path or {}).get("risk_signals",[]))
 if fn:
  if fn.get("value_flow") and "asset movement" not in risks:risks.append("asset movement")
  if fn.get("oracle_dependency") and "oracle input" not in risks:risks.append("oracle input")
  if fn.get("external_call") and "external callback" not in risks:risks.append("external callback")
  if fn.get("state_write") and "state transition" not in risks:risks.append("state transition")
  if fn.get("privileged") and "privileged boundary" not in risks:risks.append("privileged boundary")
 inv={"accounting":"protocol value and accounting quantities remain conserved across the ordered state transition","asset_flow":"assets can only move to an allowed recipient/amount under the protocol's authorization and accounting rules","external_call":"external calls cannot cause an unauthorized state/value transition before required state updates","oracle":"state-changing decisions use an authorized, sufficiently fresh and correctly normalized oracle value","privilege":"only an authorized role can perform the privileged state or asset transition","state_machine":"every state transition satisfies the protocol's required predecessor and authorization conditions","upgrade":"implementation/initialization transitions remain authorized and storage invariants remain valid","precision":"rounding and unit conversions do not create unauthorized value or accounting drift"}.get(category,"the stated security property remains true after the complete attack sequence")
 invariant=str(finding.get("security_invariant") or inv);pre=list((path or {}).get("preconditions",[])) or ["attacker can reach the identified entry point within the authorized local/test scope"]
 state={"entry_function":target,"before":finding.get("initial_state") or "record relevant balances, roles, oracle values, state variables and protocol configuration","during":risks,"after":finding.get("post_state") or "record affected balances, roles, state variables and externally observable protocol state"}
 seq=list((path or {}).get("sequence",[])) or [{"step":1,"actor":"attacker","action":"establish attacker preconditions and initial state"},{"step":2,"actor":"attacker","action":f"invoke {target} using only in-scope test inputs"},{"step":3,"actor":"protocol","action":"apply the relevant state transitions and external calls"},{"step":4,"actor":"observer","action":"evaluate the security invariant against post-state and trace"}]
 expected=str(finding.get("expected_violation") or f"{invariant} is false after the ordered sequence");affected=finding.get("affected_asset") or finding.get("affected_state") or finding.get("asset") or "affected protocol state/value flow not yet quantified";pr=(path or {}).get("reachability")
 if pr in ("unreachable","blocked","inaccessible") or (path and path.get("reachable") is False):rs="unreachable"
 elif fn and path:rs="mapped"
 elif fn or path:rs="partial"
 else:rs="unresolved"
 reach={"entry_point":target,"source_mapped":bool(fn),"path_mapped":bool(path),"status":rs,"requires_authorized_local_execution":True,"live_target_allowed":False};econ=finding.get("economic_analysis") or {};ec={"status":econ.get("status","unquantified") if isinstance(econ,dict) else "unquantified","analysis":econ,"requirement":"quantify only from source-derived balances/prices/fees or reproduced local evidence; never infer from scanner severity"}
 return {"finding_id":finding.get("id"),"title":title,"attacker_preconditions":pre,"protocol_state":state,"state_transitions":[s.get("action",s) if isinstance(s,dict) else s for s in seq],"attack_sequence":seq,"security_invariant":invariant,"expected_violation":expected,"affected_state":affected,"reachability_constraints":reach,"economic_consequence":ec,"risk_signals":risks,"protocol_mapping":{"function":fn,"attack_path":path},"status":STATUS,"validation_only":True}

def validate_plan(plan:Dict[str,Any])->List[str]:
 errors=[k for k in REQUIRED_FIELDS if not plan.get(k)];seq,reach=plan.get("attack_sequence"),plan.get("reachability_constraints")
 if not isinstance(seq,list) or len(seq)<2:errors.append("attack_sequence")
 if not isinstance(reach,dict) or not reach.get("requires_authorized_local_execution"):errors.append("authorization")
 if isinstance(reach,dict) and reach.get("live_target_allowed") is True:errors.append("live_target_policy")
 return errors

def _is_substantive(o:Dict[str,Any])->bool:
 result=str(o.get("invariant_result") or "").lower();out=str(o.get("outcome") or "").lower()
 return bool(o.get("vulnerability_reproduced") or "violat" in result or "counterexample" in result or out in {"reproduced","violation","invariant_violated"})

def correlate_execution_evidence(observations:Iterable[Dict[str,Any]])->Dict[str,Any]:
 obs=[dict(o) for o in observations];valid=[o for o in obs if isinstance(o,dict) and (o.get("finding_id") or o.get("hypothesis_id"))];malformed=[o for o in obs if o not in valid];
 def identity(o):return(str(o.get("finding_id") or ""),str(o.get("hypothesis_id") or ""),str(o.get("security_invariant") or ""))
 anchor=identity(valid[0]) if valid else None;relevant=[o for o in valid if identity(o)==anchor];unrelated_count=len(valid)-len(relevant);fps=[evidence_fingerprint(o) for o in valid];unique=list(dict.fromkeys(fps));engines={str(o.get("engine") or (o.get("execution") or {}).get("engine") or "unknown") for o in relevant};sub=[o for o in relevant if _is_substantive(o)];independent=len({e for e in engines if e!="unknown"});outcomes={str(o.get("outcome") or o.get("status") or "unknown") for o in relevant};conflicting=len(outcomes)>1;score=0.0
 if sub:score+=0.35
 score+=min(0.35,max(0,independent-1)*0.175)
 if len(sub)>=2 and len(set(evidence_fingerprint(o) for o in relevant))>=2:score+=0.20
 if conflicting:score-=0.15
 if malformed:score-=0.10
 return {"observations":obs,"unique_evidence_fingerprints":unique,"independent_engines":sorted(engines),"independent_engine_count":independent,"relevant_independent_engine_count":independent,"same_hypothesis":len({identity(o) for o in relevant})<=1,"unrelated_evidence_count":unrelated_count,"conflicting":conflicting,"substantive_evidence_count":len(sub),"malformed_evidence_count":len(malformed),"confidence_delta":round(max(0.0,min(0.9,score)),3),"repeatable":len(relevant)>=2 and len(set(evidence_fingerprint(o) for o in relevant))==1,"review_status":STATUS}
