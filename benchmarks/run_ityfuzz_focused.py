"""Run ItyFuzz against a focused repository-local reentrancy fixture with a hard kill bound."""
from __future__ import annotations
import hashlib,json,os,signal,shutil,subprocess,time
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
            p=subprocess.Popen(cmd,cwd=CWD,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:o,e=p.communicate(timeout=MAX)
            except subprocess.TimeoutExpired as x:
                os.killpg(p.pid,signal.SIGTERM)
                try:o,e=p.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid,signal.SIGKILL);o,e=p.communicate()
                blob=(o+"\n"+e).lower();payload={"status":"timeout","duration_seconds":round(time.monotonic()-started,3),"command":cmd,"cwd":str(CWD.resolve()),"stdout":o[-30000:],"stderr":e[-15000:],"stdout_sha256":sha(o),"stderr_sha256":sha(e),"focused_reentrancy_trace_observed":("reentrancybank::withdraw" in blob and "reentrancyattacker" in blob and "receive" in blob),"authorized_scope":"repository-local fixture only","max_execution_seconds":MAX,"human_review_only":True}
            else:
                blob=(o+"\n"+e).lower();payload={"status":"completed" if p.returncode==0 else "failed","returncode":p.returncode,"duration_seconds":round(time.monotonic()-started,3),"command":cmd,"cwd":str(CWD.resolve()),"stdout":o[-30000:],"stderr":e[-15000:],"stdout_sha256":sha(o),"stderr_sha256":sha(e),"focused_reentrancy_trace_observed":("reentrancybank::withdraw" in blob and "reentrancyattacker" in blob and "receive" in blob),"authorized_scope":"repository-local fixture only","max_execution_seconds":MAX,"human_review_only":True}
        except Exception as exc:
            payload={"status":"error","error":str(exc),"command":cmd,"cwd":str(CWD.resolve()),"authorized_scope":"repository-local fixture only","max_execution_seconds":MAX,"human_review_only":True}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(payload,indent=2,sort_keys=True),encoding="utf-8");print(json.dumps(payload,indent=2,sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
