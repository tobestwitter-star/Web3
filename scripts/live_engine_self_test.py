#!/usr/bin/env python3
"""Run the bundled safe security-engine fixture inside the production runtime."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from security_orchestrator import SecurityEngineOrchestrator
FIXTURE=ROOT/"benchmarks"/"engine_fixture";SLITHER_FIXTURE=ROOT/"benchmarks"/"slither_fixture"
def main()->int:
 if not FIXTURE.is_dir() or not SLITHER_FIXTURE.is_dir():raise SystemExit("production engine self-test fixtures are missing")
 orchestrator=SecurityEngineOrchestrator();inventory={item["name"]:item for item in orchestrator.inventory()};required={name:inventory.get(name,{}) for name in ("forge","slither","halmos","osv-scanner","gitleaks","ityfuzz")};missing=[name for name,meta in required.items() if not meta.get("available")]
 if missing:
  print(json.dumps({"status":"failed","missing":missing,"inventory":required},sort_keys=True),flush=True);return 1
 stage1=orchestrator.run_stage1(str(FIXTURE),timeout=60,explicit=["slither","forge","osv-scanner","gitleaks"]);halmos=orchestrator.core.run_halmos(str(FIXTURE),timeout=60);ityfuzz=orchestrator.core.run_ityfuzz(str(FIXTURE),timeout=60)
 payload={"status":"completed","inventory":required,"stage1":stage1,"halmos":halmos,"ityfuzz":ityfuzz};print(json.dumps(payload,sort_keys=True,default=str),flush=True)
 allowed={"completed","completed_with_findings"}
 for item in stage1["results"]:
  observed=item.get("integration",{}).get("status") or item.get("result",{}).get("status")
  if observed in allowed:continue
  if item.get("tool") in {"osv-scanner","gitleaks"} and item.get("result",{}).get("returncode")==1:continue
  return 1
 if halmos.get("status") not in {"completed","failed"}:return 1
 if ityfuzz.get("status") not in {"completed","failed"}:return 1
 return 0
if __name__=="__main__":raise SystemExit(main())
