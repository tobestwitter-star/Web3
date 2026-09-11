"""Bounded, provenance-preserving execution for mature Web3 security engines."""
from __future__ import annotations
import hashlib,json,os,re,shutil,subprocess,tempfile,time
from pathlib import Path
from typing import Any,Dict,List,Optional
STATUS="UNVERIFIED — HUMAN REVIEW REQUIRED"
def _sha256(text:str)->str:return hashlib.sha256(text.encode("utf-8","replace")).hexdigest()
class MatureEngineRunner:
 MAX_TIMEOUT=180; MAX_OUTPUT=50000
 def inventory(self)->Dict[str,Dict[str,Any]]:
  return {"slither":self._engine("slither","AGPL-3.0-or-later","crytic/slither"),"forge":self._engine("forge","Apache-2.0 OR MIT","foundry-rs/foundry"),"halmos":self._engine("halmos","AGPL-3.0-or-later","a16z/halmos")}
 @staticmethod
 def _engine(binary,license_name,project):
  path=shutil.which(binary);return {"binary":binary,"path":path,"available":bool(path),"license":license_name,"project":project}
 @staticmethod
 def _build_system(source_dir):
  root=Path(source_dir)
  if (root/"foundry.toml").exists():return "foundry"
  if any((root/n).exists() for n in ("hardhat.config.js","hardhat.config.ts","hardhat.config.cjs","hardhat.config.mjs")):return "hardhat"
  if (root/"package.json").exists():
   try:
    d=json.loads((root/"package.json").read_text(encoding="utf-8"));deps={**d.get("dependencies",{}),**d.get("devDependencies",{})}
    if "hardhat" in deps:return "hardhat"
   except (OSError,ValueError,TypeError):pass
  if list(root.rglob("*.sol")):return "solidity-generic"
  return "unknown"
 def _run(self,command,cwd,timeout):
  bounded=max(1,min(int(timeout),self.MAX_TIMEOUT));started=time.monotonic()
  try:
   p=subprocess.run(command,cwd=cwd,text=True,capture_output=True,timeout=bounded);out=p.stdout or "";err=p.stderr or ""
   return {"status":"completed" if p.returncode==0 else "failed","returncode":p.returncode,"stdout":out[-self.MAX_OUTPUT:],"stderr":err[-self.MAX_OUTPUT:],"stdout_sha256":_sha256(out),"stderr_sha256":_sha256(err),"duration_seconds":round(time.monotonic()-started,3),"command":command,"cwd":os.path.abspath(cwd)}
  except FileNotFoundError:return {"status":"not_available","error":f"executable not found: {command[0]}","command":command}
  except subprocess.TimeoutExpired as e:
   out=e.stdout or "";err=e.stderr or "";out=out.decode("utf-8","replace") if isinstance(out,bytes) else out;err=err.decode("utf-8","replace") if isinstance(err,bytes) else err
   return {"status":"timeout","error":f"execution exceeded {bounded}s timeout","stdout":out[-self.MAX_OUTPUT:],"stderr":err[-self.MAX_OUTPUT:],"stdout_sha256":_sha256(out),"stderr_sha256":_sha256(err),"duration_seconds":bounded,"command":command,"cwd":os.path.abspath(cwd)}
  except OSError as e:return {"status":"failed","error":str(e),"command":command,"cwd":os.path.abspath(cwd)}
 def _version(self,binary,cwd)->Optional[str]:
  if not shutil.which(binary):return None
  r=self._run([binary,"--version"],cwd,15);text=(r.get("stdout","")+"\n"+r.get("stderr","")).strip();return text.splitlines()[0][:500] if text else None
 @staticmethod
 def _slither_findings(result):
  try:data=json.loads(result.get("stdout",""))
  except (TypeError,ValueError):return []
  detectors=data.get("results",{}).get("detectors",[]) if isinstance(data,dict) else [];findings=[]
  for d in detectors if isinstance(detectors,list) else []:
   if not isinstance(d,dict):continue
   els=d.get("elements") if isinstance(d.get("elements"),list) else [];locs=[]
   for e in els:
    if not isinstance(e,dict):continue
    m=e.get("source_mapping") or {};f=m.get("filename_relative") or m.get("filename_absolute");lines=m.get("lines") or []
    if f:locs.append({"file":f,"lines":lines,"name":e.get("name"),"type":e.get("type")})
   impact=str(d.get("impact") or "informational").lower();conf=str(d.get("confidence") or "medium").lower();first=locs[0] if locs else {};line=(first.get("lines") or [None])[0]
   findings.append({"id":d.get("id") or d.get("check"),"check":d.get("check"),"title":d.get("check") or "Slither detector","description":d.get("description") or "","severity":impact,"confidence":{"high":.9,"medium":.7,"low":.45}.get(conf,.55),"locations":locs,"file":first.get("file"),"line":line,"location":f"{first.get('file')}:{line}" if first.get("file") and line else first.get("file",""),"evidence":els,"engine_evidence":{"impact":impact,"confidence_label":conf,"json_success":data.get("success") if isinstance(data,dict) else None}})
  return findings
 @staticmethod
 def _forge_findings(result):
  text=result.get("stdout","")+"\n"+result.get("stderr","");fails=re.findall(r"(?m)^\s*(?:\[FAIL(?:ED)?\]|FAIL(?:ED)?:)\s*([^\n]+)",text);return [{"id":_sha256("forge-test|"+x)[:16],"title":"Foundry test failure","description":x.strip(),"severity":"informational","confidence":.5,"category":"validation_evidence","evidence":[{"test_failure":x.strip(),"source":"forge test"}],"is_vulnerability":False} for x in fails[:100]]
 @staticmethod
 def _halmos_findings(json_data):
  findings=[]
  if isinstance(json_data,dict):
   items=json_data.get("tests") or json_data.get("results") or []
   if isinstance(items,dict): items=list(items.values())
   if isinstance(items,list):
    for item in items:
     if not isinstance(item,dict):continue
     status=str(item.get("status") or item.get("result") or "").lower()
     if status in {"fail","failed","counterexample","error"} or item.get("num_cexes",0):
      name=item.get("test") or item.get("name") or item.get("funsig") or "Halmos symbolic test"
      findings.append({"id":_sha256("halmos|"+str(name))[:16],"title":"Halmos symbolic test result","description":str(item.get("reason") or item.get("error") or status),"severity":"informational","confidence":.7,"category":"validation_evidence","evidence":[item],"is_vulnerability":False})
  return findings
 def run_slither(self,source_dir,timeout=120):
  if not os.path.isdir(source_dir):return {"tool":"slither","status":"failed","error":"source directory does not exist","findings":[]}
  meta=self.inventory()["slither"]
  if not meta["available"]:return {"tool":"slither","status":"not_available","available":False,"error":"slither is not installed","findings":[]}
  r=self._run(["slither",".","--json","-"],source_dir,timeout);findings=self._slither_findings(r);exec_status=r["status"]
  try:js=json.loads(r.get("stdout",""))
  except (TypeError,ValueError):js=None
  if r.get("returncode",0)!=0 and isinstance(js,dict) and js.get("success") is True:exec_status="completed_with_findings"
  return {"tool":"slither","status":exec_status,"available":True,"version":self._version("slither",source_dir),"execution":r,"findings":findings,"evidence_provenance":{"engine":"slither","command":r.get("command"),"cwd":r.get("cwd"),"stdout_sha256":r.get("stdout_sha256"),"stderr_sha256":r.get("stderr_sha256")},"review_status":STATUS}
 def run_foundry(self,source_dir,timeout=120):
  if not os.path.isdir(source_dir):return {"tool":"forge","status":"failed","error":"source directory does not exist","findings":[]}
  meta=self.inventory()["forge"]
  if not meta["available"]:return {"tool":"forge","status":"not_available","available":False,"error":"forge is not installed","findings":[]}
  build=self._build_system(source_dir)
  if build!="foundry":return {"tool":"forge","status":"not_applicable","available":True,"build_system":build,"error":"foundry.toml is absent; target was not mutated to create one","findings":[]}
  r=self._run(["forge","test","--json","-vvv"],source_dir,timeout)
  return {"tool":"forge","status":r["status"],"available":True,"version":self._version("forge",source_dir),"build_system":build,"execution":r,"findings":self._forge_findings(r),"evidence_provenance":{"engine":"forge","command":r.get("command"),"cwd":r.get("cwd"),"stdout_sha256":r.get("stdout_sha256"),"stderr_sha256":r.get("stderr_sha256")},"review_status":STATUS}
 def run_halmos(self,source_dir,timeout=120):
  if not os.path.isdir(source_dir):return {"tool":"halmos","status":"failed","error":"source directory does not exist","findings":[]}
  meta=self.inventory()["halmos"]
  if not meta["available"]:return {"tool":"halmos","status":"not_available","available":False,"error":"halmos is not installed","findings":[]}
  build=self._build_system(source_dir)
  if build!="foundry":return {"tool":"halmos","status":"not_applicable","available":True,"build_system":build,"error":"Halmos requires a Foundry-style target; target was not mutated","findings":[]}
  fd,path=tempfile.mkstemp(prefix="halmos-",suffix=".json");os.close(fd)
  try:
   r=self._run(["halmos","--json-output",path],source_dir,timeout)
   parsed=None
   try:parsed=json.loads(Path(path).read_text(encoding="utf-8")) if os.path.exists(path) else None
   except (OSError,ValueError,TypeError):parsed=None
   findings=self._halmos_findings(parsed)
   return {"tool":"halmos","status":r["status"],"available":True,"version":self._version("halmos",source_dir),"build_system":build,"execution":r,"json_output":parsed,"findings":findings,"evidence_provenance":{"engine":"halmos","command":r.get("command"),"cwd":r.get("cwd"),"stdout_sha256":r.get("stdout_sha256"),"stderr_sha256":r.get("stderr_sha256"),"json_output_sha256":_sha256(Path(path).read_text(encoding="utf-8")) if os.path.exists(path) else None},"review_status":STATUS}
  finally:
   try:os.unlink(path)
   except OSError:pass
 def run_core(self,source_dir,timeout=120):return {"status":"core_engine_execution_complete","build_system":self._build_system(source_dir),"engines":[self.run_slither(source_dir,timeout),self.run_foundry(source_dir,timeout)],"review_status":STATUS}
