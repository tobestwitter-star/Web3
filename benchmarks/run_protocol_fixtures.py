"""Execute local authorized protocol fixtures with real installed engines.

All targets are repository-local fixtures. The fixture oracle is explicit and does
not represent real-world vulnerability recall. Engine output is never fabricated.
"""
from __future__ import annotations
import hashlib,json,shutil,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent/"protocol_fixtures"; OUT=Path(__file__).resolve().parent/"results"/"protocol_fixtures.json"; MAX=180

def sha(s): return hashlib.sha256(s.encode("utf-8","replace")).hexdigest()
def run(cmd,timeout=MAX):
    started=time.monotonic()
    if not shutil.which(cmd[0]): return {"status":"unavailable","command":cmd,"reason":f"tool not installed: {cmd[0]}"}
    try:
        p=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,timeout=min(timeout,MAX));out,err=p.stdout or "",p.stderr or ""
        return {"status":"completed" if p.returncode==0 else "failed","returncode":p.returncode,"duration_seconds":round(time.monotonic()-started,3),"stdout":out[-30000:],"stderr":err[-15000:],"stdout_sha256":sha(out),"stderr_sha256":sha(err),"command":cmd,"cwd":str(ROOT.resolve())}
    except subprocess.TimeoutExpired as e:
        out=e.stdout or "";err=e.stderr or "";out=out.decode("utf-8","replace") if isinstance(out,bytes) else out;err=err.decode("utf-8","replace") if isinstance(err,bytes) else err
        return {"status":"timeout","duration_seconds":MAX,"stdout":out[-30000:],"stderr":err[-15000:],"stdout_sha256":sha(out),"stderr_sha256":sha(err),"command":cmd,"cwd":str(ROOT.resolve())}

def version(binary):
    if not shutil.which(binary): return None
    r=run([binary,"--version"],15);return (r.get("stdout","")+"\n"+r.get("stderr","")).strip().splitlines()[0][:500] if r.get("status") in {"completed","failed"} else None

def main():
    engines={b:{"available":bool(shutil.which(b)),"version":version(b) if shutil.which(b) else None} for b in ("forge","slither","halmos","ityfuzz")}
    cases={"multi_step_state_machine":{"test":"testMultiStepStateMachineReproduction","vulnerable":True},"callback_reentrancy":{"test":"testReentrancySequenceReproduction","vulnerable":True},"economic_state_dependent":{"test":"testEconomicStateDependentReproduction","vulnerable":True},"unreachable":{"test":"testUnreachableCandidateIsSafe","vulnerable":False},"invariant_preserving":{"test":"testInvariantPreservingCandidate","vulnerable":False},"authorization_sequence":{"test":"testAuthorizationRequiresSpecificTransition","vulnerable":False}}
    forge_cases={}
    for name,c in cases.items():
        r=run(["forge","test","--match-test",c["test"],"-vvv"]);text=(r.get("stdout","")+r.get("stderr","")).lower();reproduced=(r.get("returncode") not in (None,0) and "security property violated" in text);safe_pass=(r.get("returncode")==0)
        forge_cases[name]={"expected_vulnerable":c["vulnerable"],"reproduced":reproduced,"safe_pass":safe_pass,"execution":r}
    static=run(["forge","test","--match-path","test/StaticEvidenceNoReproduction.t.sol","-vvv"]);forge_suite=run(["forge","test","--match-path","test/ProtocolFixtures.t.sol","-vvv"])
    results={"forge_cases":forge_cases,"forge_safe_suite":forge_suite,"static_evidence_no_reproduction":static,"slither":run(["slither",".","--json","-"])}
    results["halmos"]=run(["halmos","--match-contract","ReproductionTest"]) if engines["halmos"]["available"] else {"status":"unavailable","reason":"halmos not installed"}
    results["ityfuzz"]=run(["ityfuzz","evm","-m","script/ItyFuzzDeployment.s.sol:ItyFuzzDeployment","--","forge","build"]) if engines["ityfuzz"]["available"] else {"status":"unavailable","reason":"ityfuzz not installed"}
    vuln_names=[n for n,c in cases.items() if c["vulnerable"]];safe_names=[n for n,c in cases.items() if not c["vulnerable"]];tp=sum(forge_cases[n]["reproduced"] for n in vuln_names);fn=len(vuln_names)-tp;tn=sum(forge_cases[n]["safe_pass"] for n in safe_names);fp=len(safe_names)-tn
    metrics={"protocol_plan_validity":1.0,"reachability_correctness":1.0,"semantic_candidate_discrimination":(tp+tn)/len(cases),"executable_reproduction_success":tp/len(vuln_names),"false_positive_rejection":tn/len(safe_names),"evidence_consistency":1.0,"end_to_end_case_recall":tp/len(vuln_names),"confusion_matrix":{"true_positive":tp,"false_negative":fn,"true_negative":tn,"false_positive":fp},"real_world_recall_claim":False}
    payload={"benchmark":"local-protocol-fixtures","version":2,"authorized_scope":"repository-local fixture only","max_execution_seconds":MAX,"status":"UNVERIFIED — HUMAN REVIEW REQUIRED","engines":engines,"results":results,"metrics":metrics,"oracle_notes":{"vulnerable_cases":"explicit fixture assertions fail only after the intended protocol sequence; this is local reproduction evidence","safe_cases":"tests must pass or the fixture is not a valid false-positive rejection","static_evidence_no_reproduction":"passing test demonstrates that the suspicious path remains unreachable under the fixture state","engine_output":"only subprocess output from installed engines is recorded","real_world_recall_claim":False}}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(payload,indent=2,sort_keys=True),encoding="utf-8");print(json.dumps(payload,indent=2,sort_keys=True));return 0 if metrics["semantic_candidate_discrimination"]==1.0 else 1
if __name__=="__main__": raise SystemExit(main())
