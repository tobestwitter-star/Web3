"""Run ItyFuzz against a focused repository-local reentrancy fixture."""
from __future__ import annotations
import hashlib,json,shutil,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];CWD=ROOT/"benchmarks"/"protocol_fixtures";OUT=ROOT/"benchmarks"/"results"/"ityfuzz_focused.json";MAX=60

def sha(s):return hashlib.sha256(s.encode("utf-8","replace")).hexdigest()

def main():
    cmd=["ityfuzz","evm","-m","script/ItyFuzzReentrancyDeployment.s.sol:ItyFuzzReentrancyDeployment","--","forge","build"]
    if not shutil.which("ityfuzz"):
        payload={"status":"unavailable","command":cmd,"reason":"ityfuzz not installed","authorized_scope":"repository-local fixture only"}
    else:
        started=time.monotonic()
        try:
            p=subprocess.run(cmd,cwd=CWD,text=True,capture_output=True,timeout=MAX);o,e=p.stdout or "",p.stderr or ""
            blob=(o+"\n"+e).lower();reentrancy_trace=("reentrancybank::withdraw" in blob and "reentrancyattacker" in blob and "receive" in blob)
            payload={"status":"completed" if p.returncode==0 else "failed","returncode":p.returncode,"duration_seconds":round(time.monotonic()-started,3),"command":cmd,"cwd":str(CWD.resolve()),"stdout":o[-30000:],"stderr":e[-15000:],"stdout_sha256":sha(o),"stderr_sha256":sha(e),"focused_reentrancy_trace_observed":reentrancy_trace,"authorized_scope":"repository-local fixture only","max_execution_seconds":MAX,"human_review_only":True}
        except subprocess.TimeoutExpired as x:
            o=x.stdout or "";e=x.stderr or "";o=o.decode("utf-8","replace") if isinstance(o,bytes) else o;e=e.decode("utf-8","replace") if isinstance(e,bytes) else e;blob=(o+"\n"+e).lower()
            payload={"status":"timeout","duration_seconds":MAX,"command":cmd,"cwd":str(CWD.resolve()),"stdout":o[-30000:],"stderr":e[-15000:],"stdout_sha256":sha(o),"stderr_sha256":sha(e),"focused_reentrancy_trace_observed":("reentrancybank::withdraw" in blob and "reentrancyattacker" in blob and "receive" in blob),"authorized_scope":"repository-local fixture only","max_execution_seconds":MAX,"human_review_only":True}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(payload,indent=2,sort_keys=True),encoding="utf-8");print(json.dumps(payload,indent=2,sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
