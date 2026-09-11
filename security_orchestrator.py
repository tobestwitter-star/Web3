"""Staged orchestration for optional local Web3 security engines."""
from __future__ import annotations
import os,shutil,subprocess,time
from typing import Any,Dict,Iterable,List
from security_toolchain import SecurityToolchain, STATUS
from mature_engine_runner import MatureEngineRunner
ENGINE_POLICY={"slither":{"stage":1,"binary":"slither","questions":{"broad","reentrancy","access_control","delegatecall","oracle","accounting"}},"forge":{"stage":1,"binary":"forge","questions":{"baseline","reproduction","invariant","reentrancy","state_machine","accounting"}},"osv-scanner":{"stage":1,"binary":"osv-scanner","questions":{"dependencies"}},"gitleaks":{"stage":1,"binary":"gitleaks","questions":{"secrets"}},"sourcify":{"stage":1,"binary":None,"questions":{"verification"}},"ityfuzz":{"stage":2,"binary":"ityfuzz","questions":{"execution_path","reentrancy","state_machine","oracle","accounting"}},"halmos":{"stage":2,"binary":"halmos","questions":{"symbolic","state_machine","accounting","access_control"}},"wake":{"stage":3,"binary":"wake","questions":{"independent_static","broad"}},"medusa":{"stage":3,"binary":"medusa","questions":{"state_machine","invariant","fuzz"}},"echidna":{"stage":3,"binary":"echidna-test","questions":{"state_machine","invariant","fuzz"}}}
QUESTION_MAP={"reentrancy":{"slither","forge","ityfuzz"},"state_machine":{"forge","halmos","medusa","echidna","ityfuzz"},"symbolic":{"halmos"},"dependencies":{"osv-scanner"},"secrets":{"gitleaks"},"verification":{"sourcify"},"execution_path":{"forge","ityfuzz"},"independent_static":{"wake"},"invariant":{"forge","medusa","echidna"},"broad":{"slither","forge"}}
class SecurityEngineOrchestrator:
 def __init__(self,toolchain:SecurityToolchain|None=None):self.toolchain=toolchain or SecurityToolchain();self.core=MatureEngineRunner()
 def inventory(self)->List[Dict[str,Any]]:
  base={x["name"]:x for x in self.toolchain.inventory()}
  for name,policy in ENGINE_POLICY.items():
   if name not in base:
    binary=policy.get("binary");base[name]={"name":name,"binary":shutil.which(binary) if binary else None,"available":bool(binary and shutil.which(binary)),"kind":"verification-service" if name=="sourcify" else "external-engine","license":"service/protocol; no local binary","project":"ethereum/sourcify" if name=="sourcify" else "unknown"}
  for name,meta in self.core.inventory().items():
   base[name]={**base.get(name,{}),"name":name,"binary":meta["binary"],"available":meta["available"],"path":meta["path"],"license":meta["license"],"project":meta["project"]}
  return list(base.values())
 def _run(self,command:List[str],cwd:str,timeout:int)->Dict[str,Any]:
  bounded=max(1,min(int(timeout),180));started=time.monotonic()
  try:
   p=subprocess.run(command,cwd=cwd,text=True,capture_output=True,timeout=bounded);return {"status":"completed" if p.returncode==0 else "failed","returncode":p.returncode,"stdout":p.stdout[-30000:],"stderr":p.stderr[-15000:],"duration_seconds":round(time.monotonic()-started,3)}
  except FileNotFoundError:return {"status":"not_available","error":f"tool not installed: {command[0]}"}
  except subprocess.TimeoutExpired:return {"status":"timeout","error":f"tool exceeded {bounded}s limit","duration_seconds":bounded}
  except OSError as exc:return {"status":"failed","error":str(exc)}
 @staticmethod
 def _question_for_finding(finding:Dict[str,Any])->str:
  text=" ".join(str(finding.get(k,"")) for k in ("title","description","category")).lower()
  if any(x in text for x in ("reentr","callback")):return "reentrancy"
  if any(x in text for x in ("state machine","state transition","invariant")):return "state_machine"
  if any(x in text for x in ("oracle","price manipulation")):return "oracle"
  if any(x in text for x in ("accounting","rounding","precision","fee")):return "accounting"
  if any(x in text for x in ("access control","privilege","authorization")):return "access_control"
  if any(x in text for x in ("delegatecall","upgrade","proxy")):return "delegatecall"
  return "execution_path"
 def _selected(self,question:str,stage:int,available:Dict[str,Dict[str,Any]],explicit:Iterable[str]|None=None)->List[str]:
  allowed=set(explicit) if explicit else QUESTION_MAP.get(question,{"slither","forge"});return [n for n in allowed if ENGINE_POLICY.get(n,{}).get("stage")==stage and available.get(n,{}).get("available")]
 def run_stage1(self,source_dir:str,timeout:int=120,explicit:Iterable[str]|None=None)->Dict[str,Any]:
  inventory={x["name"]:x for x in self.inventory()};selected=[n for n in (explicit or ("slither","forge","osv-scanner","gitleaks")) if inventory.get(n,{}).get("available")];results=[]
  for name in selected:
   if name=="slither":core=self.core.run_slither(source_dir,timeout);results.append({"tool":name,"stage":1,"question":"broad","result":core.get("execution",{}),"findings":core.get("findings",[]),"integration":core,"review_status":STATUS});continue
   if name=="forge":core=self.core.run_foundry(source_dir,timeout);results.append({"tool":name,"stage":1,"question":"baseline","result":core.get("execution",{}),"findings":core.get("findings",[]),"integration":core,"review_status":STATUS});continue
   command=["osv-scanner","scan","--format","json","--recursive","."] if name=="osv-scanner" else ["gitleaks","detect","--no-banner","--report-format","json","--report-path","-"]
   r=self._run(command,source_dir,timeout);results.append({"tool":name,"stage":1,"question":"broad","result":r,"findings":self.toolchain.parse_result(name,r),"review_status":STATUS})
  return {"stage":1,"selected":selected,"results":results,"resource_policy":{"timeout_seconds":min(int(timeout),180),"max_parallel":1}}
 def run_for_candidates(self,source_dir:str,findings:List[Dict[str,Any]],timeout:int=180)->Dict[str,Any]:
  inventory={x["name"]:x for x in self.inventory()};candidates=sorted(findings or [],key=lambda f:float(f.get("priority",f.get("priority_score",0)) or 0),reverse=True)[:10];decisions=[]
  for finding in candidates:
   question=self._question_for_finding(finding);stage2=self._selected(question,2,inventory);stage3=self._selected(question,3,inventory);chosen=stage2[:1] if stage2 else []
   if not chosen and stage3 and float(finding.get("priority",0) or 0)>=70:chosen=stage3[:1]
   evidence=[]
   for name in chosen:
    if name=="halmos":result=self.core.run_halmos(source_dir,min(int(timeout),180))
    else:
     command={"ityfuzz":["ityfuzz"],"medusa":["medusa","fuzz"],"echidna":["echidna-test","."]}.get(name)
     if not command:continue
     result=self._run(command,source_dir,min(int(timeout),180))
    evidence.append({"tool":name,"stage":ENGINE_POLICY[name]["stage"],"question":question,"result":result,"review_status":STATUS})
   decisions.append({"finding_id":finding.get("id"),"question":question,"selected_engines":chosen,"selection_reason":"candidate-driven escalation; bounded to at most one heavyweight engine per candidate","evidence":evidence,"review_status":STATUS})
  return {"stage":2,"decisions":decisions,"resource_policy":{"max_heavy_engines_per_candidate":1,"timeout_seconds":min(int(timeout),180)}}
 def orchestrate(self,source_dir:str,findings:List[Dict[str,Any]]|None=None,timeout:int=120,explicit:Iterable[str]|None=None)->Dict[str,Any]:
  if not os.path.isdir(source_dir):return {"status":"error","reason":"source directory does not exist","review_status":STATUS}
  build=self.toolchain.detect_build(source_dir);stage1=self.run_stage1(source_dir,timeout,explicit);candidate_input=findings or [f for r in stage1["results"] for f in r.get("findings",[])];stage2=self.run_for_candidates(source_dir,candidate_input,min(timeout,180)) if candidate_input else {"stage":2,"decisions":[],"skipped":"no credible candidates"}
  return {"status":"orchestration_complete","build":build,"inventory":self.inventory(),"stage1":stage1,"stage2":stage2,"stage3":{"status":"deferred","reason":"deep engines require a high-value candidate and explicit escalation"},"findings_are_evidence_only":True,"review_status":STATUS}
