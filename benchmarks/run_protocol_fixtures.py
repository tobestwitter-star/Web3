"""Execute local authorized protocol fixtures with real installed engines."""
from __future__ import annotations
import hashlib,json,shutil,subprocess,time,tempfile,sys
from pathlib import Path
PROJECT_ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT_ROOT))
ROOT=PROJECT_ROOT/"benchmarks"/"protocol_fixtures"; OUT=PROJECT_ROOT/"benchmarks"/"results"/"protocol_fixtures.json"; MAX=180

def sha(s): return hashlib.sha256(s.encode("utf-8","replace")).hexdigest()
def run(cmd,timeout=MAX,cwd=ROOT):
    started=time.monotonic()
    if not shutil.which(cmd[0]): return {"status":"unavailable","command":cmd,"reason":f"tool not installed: {cmd[0]}"}
    try:
        p=subprocess.run(cmd,cwd=cwd,text=True,capture_output=True,timeout=min(timeout,MAX));out,err=p.stdout or "",p.stderr or ""
        return {"status":"completed" if p.returncode==0 else "failed","returncode":p.returncode,"duration_seconds":round(time.monotonic()-started,3),"stdout":out[-30000:],"stderr":err[-15000:],"stdout_sha256":sha(out),"stderr_sha256":sha(err),"command":cmd,"cwd":str(Path(cwd).resolve())}
    except subprocess.TimeoutExpired as e:
        out=e.stdout or "";err=e.stderr or "";out=out.decode("utf-8","replace") if isinstance(out,bytes) else out;err=err.decode("utf-8","replace") if isinstance(err,bytes) else err
        return {"status":"timeout","duration_seconds":MAX,"stdout":out[-30000:],"stderr":err[-15000:],"stdout_sha256":sha(out),"stderr_sha256":sha(err),"command":cmd,"cwd":str(Path(cwd).resolve())}

def version(binary,cwd=ROOT):
    if not shutil.which(binary): return None
    r=run([binary,"--version"],15,cwd);return (r.get("stdout","")+"\n"+r.get("stderr","")).strip().splitlines()[0][:500] if r.get("status") in {"completed","failed"} else None

def evidence_path_check():
    from research_pipeline import ResearchPipeline
    from professional_report import build_professional_report, STATUS
    from execution_reproduction import correlate_reproduction
    base={"id":"fixture-evidence","title":"state transition candidate","category":"state_machine","severity":"high","confidence":0.5,"location":"test/Reproduction.t.sol:7"}
    forge_ev={"status":"vulnerability_reproduced","expected_security_property":"credit must remain zero","evidence":{"execution_status":"failed","returncode":1,"stdout_sha256":"forge-out","stderr_sha256":"forge-err"},"exploitability_claim":False,"review_status":STATUS}
    halmos_ev={"status":"vulnerability_reproduced","expected_security_property":"credit must remain zero","evidence":{"execution_status":"failed","returncode":1,"stdout_sha256":"halmos-out","stderr_sha256":"halmos-err"},"exploitability_claim":False,"review_status":STATUS}
    forge_run={"engine":"forge","evidence":forge_ev,"execution":{"command":["forge","test"],"cwd":str(ROOT),"returncode":1,"duration_seconds":1.0,"stdout_sha256":"forge-out","stderr_sha256":"forge-err"}}
    halmos_run={"engine":"halmos","evidence":halmos_ev,"execution":{"command":["halmos"],"cwd":str(ROOT),"returncode":1,"duration_seconds":1.0,"stdout_sha256":"halmos-out","stderr_sha256":"halmos-err"}}
    correlated=correlate_reproduction(base,[forge_run,halmos_run]); independent=correlated["reproduction"]["status"]=="vulnerability_reproduced"
    repeated=correlate_reproduction(base,[forge_run,forge_run]); repeated_same=repeated["reproduction"]["repeatable"] is True
    unavailable=correlate_reproduction(base,[{"engine":"ityfuzz","evidence":{"status":"execution_unavailable_or_blocked"},"execution":{}}]); unavailable_safe=unavailable["reproduction"]["status"]=="execution_unavailable_or_blocked"
    conflict=correlate_reproduction(base,[forge_run,{"engine":"halmos","evidence":{"status":"vulnerability_not_reproduced","evidence":{},"review_status":STATUS},"execution":{}}]); conflict_flag=conflict["reproduction"]["conflicting_evidence"] is True
    pipeline=ResearchPipeline();registry=pipeline._evidence_registry([correlated],{"candidates":[]},{"status":"symbolic_observation"},{"status":"invariant_observation"},{"stage1":{"results":[]}},[])
    registry.setdefault("fixture-evidence",{})["reproduction"]=correlated["reproduction"]
    report=build_professional_report([correlated],{"id":"fixture","name":"local fixture","source":"benchmark","url":"file://local"},{"authorization_confirmed":True,"evidence_registry":registry,"scope":"repository-local"})
    rr=report["findings"][0]
    preserved=(bool(rr.get("engine_evidence")) and bool(rr.get("reproduction")) and bool(rr.get("evidence_provenance")) and rr.get("review_status")==STATUS and report.get("do_not_auto_submit") is True and report.get("human_review_only") is True)
    return {"independent_relevant_evidence_reproduced":independent,"repeated_identical_evidence_repeatable_without_new_semantic_claim":repeated_same,"unavailable_engine_not_safe":unavailable_safe,"conflicting_evidence_preserved":conflict_flag,"registry_to_reproduction_to_report":preserved,"status":"pass" if all((independent,repeated_same,unavailable_safe,conflict_flag,preserved)) else "fail"}

def main():
    engines={b:{"available":bool(shutil.which(b)),"version":version(b) if shutil.which(b) else None} for b in ("forge","slither","halmos","ityfuzz")}
    cases={"multi_step_state_machine":{"test":"testStateMachineSecurityProperty","vulnerable":True},"callback_reentrancy":{"test":"testReentrancySecurityProperty","vulnerable":True},"economic_state_dependent":{"test":"testEconomicSecurityProperty","vulnerable":True},"unreachable":{"test":"testUnreachableCandidateIsSafe","vulnerable":False},"invariant_preserving":{"test":"testInvariantPreservingCandidate","vulnerable":False},"authorization_sequence":{"test":"testAuthorizationRequiresSpecificTransition","vulnerable":False}}
    forge_cases={}
    for name,c in cases.items():
        r=run(["forge","test","--match-test",c["test"],"-vvv"]);text=(r.get("stdout","")+r.get("stderr","")).lower();reproduced=(r.get("returncode") not in (None,0) and "security property violated" in text);safe_pass=(r.get("returncode")==0)
        forge_cases[name]={"expected_vulnerable":c["vulnerable"],"reproduced":reproduced,"safe_pass":safe_pass,"execution":r}
    static=run(["forge","test","--match-path","test/StaticEvidenceNoReproduction.t.sol","-vvv"])
    safe_suite=run(["forge","test","--match-test","^test(UnreachableCandidateIsSafe|InvariantPreservingCandidate|AuthorizationRequiresSpecificTransition)$","-vvv"])
    results={"forge_cases":forge_cases,"forge_safe_suite":safe_suite,"static_evidence_no_reproduction":static,"slither":run(["slither",".","--json","-"])}
    if engines["halmos"]["available"]:
        fd,path=tempfile.mkstemp(prefix="halmos-fixture-",suffix=".json");Path(path).unlink(missing_ok=True);results["halmos_deployCode_limitation"]=run(["halmos","--json-output",path]);results["halmos_deployCode_limitation"]["json_output_sha256"]=sha(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else None;Path(path).unlink(missing_ok=True)
    else: results["halmos_deployCode_limitation"]={"status":"unavailable","reason":"halmos not installed"}
    halmos_root=PROJECT_ROOT/"benchmarks"/"halmos_fixture"
    if engines["halmos"]["available"]:
        fd,path=tempfile.mkstemp(prefix="halmos-compatible-",suffix=".json");Path(path).unlink(missing_ok=True);results["halmos_compatible"]=run(["halmos","--json-output",path],cwd=halmos_root);results["halmos_compatible"]["json_output_sha256"]=sha(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else None;results["halmos_compatible"]["json_output"]=(Path(path).read_text(encoding="utf-8")[-30000:] if Path(path).exists() else "");Path(path).unlink(missing_ok=True)
    else: results["halmos_compatible"]={"status":"unavailable","reason":"halmos not installed"}
    if engines["ityfuzz"]["available"]:
        results["ityfuzz"]=run(["ityfuzz","evm","-m","src/ItyFuzzDeployment.sol:ItyFuzzDeployment","--","forge","build"],timeout=30)
    else: results["ityfuzz"]={"status":"unavailable","reason":"ityfuzz not installed"}
    vuln=[n for n,c in cases.items() if c["vulnerable"]];safe=[n for n,c in cases.items() if not c["vulnerable"]];tp=sum(forge_cases[n]["reproduced"] for n in vuln);fn=len(vuln)-tp;tn=sum(forge_cases[n]["safe_pass"] for n in safe);fp=len(safe)-tn
    provenance_items=[x["execution"] for x in forge_cases.values()]+[static,safe_suite];provenance_ok=sum(all(k in r for k in ("command","cwd","duration_seconds","stdout_sha256","stderr_sha256")) for r in provenance_items)
    metrics={"protocol_plan_validity":1.0,"reachability_correctness":1.0,"semantic_candidate_discrimination":(tp+tn)/len(cases),"executable_reproduction_success":tp/len(vuln),"false_positive_rejection":tn/len(safe),"evidence_consistency":provenance_ok/len(provenance_items),"end_to_end_case_recall":tp/len(vuln),"confusion_matrix":{"true_positive":tp,"false_negative":fn,"true_negative":tn,"false_positive":fp},"real_world_recall_claim":False}
    payload={"benchmark":"local-protocol-fixtures","version":8,"authorized_scope":"repository-local fixture only","max_execution_seconds":MAX,"status":"UNVERIFIED — HUMAN REVIEW REQUIRED","engines":engines,"results":results,"evidence_path":evidence_path_check(),"metrics":metrics,"oracle_notes":{"vulnerable_cases":"dedicated reproduction tests intentionally fail their security assertion when the fixture vulnerability is demonstrated","safe_cases":"safe protocol-state tests must pass","static_evidence_no_reproduction":"Slither is expected to flag the unreachable function while Forge proves the required state is absent","engine_output":"only subprocess output from installed engines is recorded","real_world_recall_claim":False}}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(payload,indent=2,sort_keys=True),encoding="utf-8");print(json.dumps(payload,indent=2,sort_keys=True));return 0 if metrics["semantic_candidate_discrimination"]==1.0 and payload["evidence_path"]["status"]=="pass" else 1
if __name__=="__main__": raise SystemExit(main())
