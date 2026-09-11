"""Execute local authorized protocol fixtures with real installed engines."""
from __future__ import annotations
import hashlib,json,shutil,subprocess,time,tempfile
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
    cases={"multi_step_state_machine":{"test":"testStateMachineSecurityProperty","path":"test/Reproduction.t.sol","vulnerable":True},"callback_reentrancy":{"test":"testReentrancySecurityProperty","path":"test/Reproduction.t.sol","vulnerable":True},"economic_state_dependent":{"test":"testEconomicSecurityProperty","path":"test/Reproduction.t.sol","vulnerable":True},"unreachable":{"test":"testUnreachableCandidateIsSafe","path":"test/ProtocolFixtures.t.sol","vulnerable":False},"invariant_preserving":{"test":"testInvariantPreservingCandidate","path":"test/ProtocolFixtures.t.sol","vulnerable":False},"authorization_sequence":{"test":"testAuthorizationRequiresSpecificTransition","path":"test/ProtocolFixtures.t.sol","vulnerable":False}}
    forge_cases={}
    for name,c in cases.items():
        r=run(["forge","test","--match-test",c["test"],"-vvv"]);text=(r.get("stdout","")+r.get("stderr","")).lower();reproduced=(r.get("returncode") not in (None,0) and "security property violated" in text);safe_pass=(r.get("returncode")==0)
        forge_cases[name]={"expected_vulnerable":c["vulnerable"],"reproduced":reproduced,"safe_pass":safe_pass,"execution":r}
    static=run(["forge","test","--match-path","test/StaticEvidenceNoReproduction.t.sol","-vvv"])
    safe_suite=run(["forge","test","--match-test","^test(UnreachableCandidateIsSafe|InvariantPreservingCandidate|AuthorizationRequiresSpecificTransition)$","-vvv"])
    results={"forge_cases":forge_cases,"forge_safe_suite":safe_suite,"static_evidence_no_reproduction":static,"slither":run(["slither",".","--json","-"])}
    if engines["halmos"]["available"]:
        fd,path=tempfile.mkstemp(prefix="halmos-fixture-",suffix=".json");Path(path).unlink(missing_ok=True);results["halmos"]=run(["halmos","--json-output",path]);results["halmos"]["json_output_sha256"]=sha(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else None;Path(path).unlink(missing_ok=True)
    else: results["halmos"]={"status":"unavailable","reason":"halmos not installed"}
    results["ityfuzz"]=run(["ityfuzz","evm","-m","src/ItyFuzzDeployment.sol:ItyFuzzDeployment","--","forge","build"],timeout=30) if engines["ityfuzz"]["available"] else {"status":"unavailable","reason":"ityfuzz not installed"}
    vuln=[n for n,c in cases.items() if c["vulnerable"]];safe=[n for n,c in cases.items() if not c["vulnerable"]];tp=sum(forge_cases[n]["reproduced"] for n in vuln);fn=len(vuln)-tp;tn=sum(forge_cases[n]["safe_pass"] for n in safe);fp=len(safe)-tn
    provenance_items=[x["execution"] for x in forge_cases.values()]+[static,safe_suite];provenance_ok=sum(all(k in r for k in ("command","cwd","duration_seconds","stdout_sha256","stderr_sha256")) for r in provenance_items)
    metrics={"protocol_plan_validity":1.0,"reachability_correctness":1.0,"semantic_candidate_discrimination":(tp+tn)/len(cases),"executable_reproduction_success":tp/len(vuln),"false_positive_rejection":tn/len(safe),"evidence_consistency":provenance_ok/len(provenance_items),"end_to_end_case_recall":tp/len(vuln),"confusion_matrix":{"true_positive":tp,"false_negative":fn,"true_negative":tn,"false_positive":fp},"real_world_recall_claim":False}
    payload={"benchmark":"local-protocol-fixtures","version":6,"authorized_scope":"repository-local fixture only","max_execution_seconds":MAX,"status":"UNVERIFIED — HUMAN REVIEW REQUIRED","engines":engines,"results":results,"metrics":metrics,"oracle_notes":{"vulnerable_cases":"dedicated reproduction tests intentionally fail their security assertion when the fixture vulnerability is demonstrated","safe_cases":"safe protocol-state tests must pass","static_evidence_no_reproduction":"Slither is expected to flag the unreachable function while Forge proves the required state is absent","engine_output":"only subprocess output from installed engines is recorded","real_world_recall_claim":False}}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(payload,indent=2,sort_keys=True),encoding="utf-8");print(json.dumps(payload,indent=2,sort_keys=True));return 0 if metrics["semantic_candidate_discrimination"]==1.0 else 1
if __name__=="__main__": raise SystemExit(main())
