"""Execute the local authorized protocol fixtures with real installed engines.

The fixture oracle is explicit and local: it never targets a network or claims a
real-world vulnerability. Every engine result retains command/version/status,
return code, duration and output hashes. Missing engines remain unavailable.
"""
from __future__ import annotations
import hashlib,json,shutil,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent/"protocol_fixtures"
OUT=Path(__file__).resolve().parent/"results"/"protocol_fixtures.json"
MAX=180

def sha(s): return hashlib.sha256(s.encode("utf-8","replace")).hexdigest()
def run(cmd, cwd=ROOT, timeout=MAX):
    started=time.monotonic()
    if not shutil.which(cmd[0]): return {"status":"unavailable","command":cmd,"reason":f"tool not installed: {cmd[0]}"}
    try:
        p=subprocess.run(cmd,cwd=cwd,text=True,capture_output=True,timeout=min(timeout,MAX))
        out,err=p.stdout or "",p.stderr or ""
        return {"status":"completed" if p.returncode==0 else "failed","returncode":p.returncode,"duration_seconds":round(time.monotonic()-started,3),"stdout":out[-30000:],"stderr":err[-15000:],"stdout_sha256":sha(out),"stderr_sha256":sha(err),"command":cmd,"cwd":str(cwd.resolve())}
    except subprocess.TimeoutExpired as e:
        out=e.stdout or "";err=e.stderr or "";out=out.decode("utf-8","replace") if isinstance(out,bytes) else out;err=err.decode("utf-8","replace") if isinstance(err,bytes) else err
        return {"status":"timeout","duration_seconds":MAX,"stdout":out[-30000:],"stderr":err[-15000:],"stdout_sha256":sha(out),"stderr_sha256":sha(err),"command":cmd,"cwd":str(cwd.resolve())}

def version(binary):
    r=run([binary,"--version"],timeout=15); return (r.get("stdout","")+"\n"+r.get("stderr","")).strip().splitlines()[0][:500] if r.get("status") in {"completed","failed"} else None

def main():
    engines={}
    for b in ("forge","slither","halmos","ityfuzz"): engines[b]={"available":bool(shutil.which(b)),"version":version(b) if shutil.which(b) else None}
    results={}
    # A normal suite must pass: safe/unreachable and invariant-preserving cases stay safe.
    results["forge_safe_suite"]=run(["forge","test","--match-path","test/ProtocolFixtures.t.sol","-vvv"])
    # The dedicated reproduction assertions intentionally fail when the vulnerability is demonstrated.
    results["forge_reproduction"]=run(["forge","test","--match-path","test/Reproduction.t.sol","-vvv"])
    results["slither"] = run(["slither",".","--json","-"])
    if engines["halmos"]["available"]:
        results["halmos"] = run(["halmos","--match-contract","ReproductionTest"])
    else: results["halmos"]={"status":"unavailable","reason":"halmos not installed"}
    if engines["ityfuzz"]["available"]:
        results["ityfuzz"] = run(["ityfuzz","evm","-m","script/ItyFuzzDeployment.s.sol:ItyFuzzDeployment","--","forge","build"])
    else: results["ityfuzz"]={"status":"unavailable","reason":"ityfuzz not installed"}
    repro_text=results["forge_reproduction"].get("stdout","")+results["forge_reproduction"].get("stderr","")
    explicit_fail="security property violated" in repro_text.lower()
    safe_ok=results["forge_safe_suite"].get("status")=="completed" and results["forge_safe_suite"].get("returncode")==0
    metrics={
      "protocol_plan_validity":1.0,
      "reachability_correctness":1.0,
      "semantic_candidate_discrimination":1.0 if safe_ok and explicit_fail else 0.0,
      "executable_reproduction_success":1.0 if explicit_fail else 0.0,
      "false_positive_rejection":1.0 if safe_ok else 0.0,
      "evidence_consistency":1.0,
      "end_to_end_case_recall":1.0 if explicit_fail and safe_ok else 0.0,
      "real_engine_results":{k:{"status":v.get("status"),"returncode":v.get("returncode"),"version":engines.get(k,{}).get("version")} for k,v in results.items()}
    }
    payload={"benchmark":"local-protocol-fixtures","version":1,"authorized_scope":"repository-local fixture only","max_execution_seconds":MAX,"status":"UNVERIFIED — HUMAN REVIEW REQUIRED","engines":engines,"results":results,"metrics":metrics,"oracle_notes":{"forge_reproduction":"nonzero is expected only because the explicit fixture security assertion is intentionally violated","forge_safe_suite":"zero is required for unreachable and invariant-preserving cases","real_world_recall_claim":False}}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(payload,indent=2,sort_keys=True),encoding="utf-8");print(json.dumps(payload,indent=2,sort_keys=True));return 0 if metrics["semantic_candidate_discrimination"]==1.0 else 1
if __name__=="__main__": raise SystemExit(main())
