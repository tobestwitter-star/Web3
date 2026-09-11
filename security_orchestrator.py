"""Staged orchestration for optional local Web3 security engines."""
from __future__ import annotations
import hashlib,json,os,shutil,subprocess,time
from typing import Any,Dict,Iterable,List
from security_toolchain import SecurityToolchain, STATUS
from mature_engine_runner import MatureEngineRunner
ENGINE_POLICY={"slither":{"stage":1,"binary":"slither","questions":{"broad","reentrancy","access_control","delegatecall","oracle","accounting"}},"forge":{"stage":1,"binary":"forge","questions":{"baseline","reproduction","invariant","reentrancy","state_machine","accounting","execution_path"}},"osv-scanner":{"stage":1,"binary":"osv-scanner","questions":{"dependencies"}},"gitleaks":{"stage":1,"binary":"gitleaks","questions":{"secrets"}},"sourcify":{"stage":1,"binary":None,"questions":{"verification"}},"ityfuzz":{"stage":2,"binary":"ityfuzz","questions":{"execution_path","reentrancy","state_machine","oracle","accounting"}},"halmos":{"stage":2,"binary":"halmos","questions":{"symbolic","state_machine","accounting","access_control"}},"wake":{"stage":3,"binary":"wake","questions":{"independent_static","broad"}},"medusa":{"stage":3,"binary":"medusa","questions":{"state_machine","invariant","fuzz"}},"echidna":{"stage":3,"binary":"echidna-test","questions":{"state_machine","invariant","fuzz"}}}
QUESTION_MAP={"reentrancy":{"slither","forge","ityfuzz"},"state_machine":{"forge","halmos","ityfuzz","medusa","echidna"},"symbolic":{"halmos"},"dependencies":{"osv-scanner"},"secrets":{"gitleaks"},"verification":{"sourcify"},"execution_path":{"forge","ityfuzz"},"invariant":{"forge","medusa","echidna"},"broad":{"slither","forge"},"oracle":{"slither","ityfuzz"},"accounting":{"slither","forge","ityfuzz"},"access_control":{"slither","halmos"},"delegatecall":{"slither"}}
class SecurityEngineOrchestrator:
 def __init__(self,toolchain:SecurityToolchain|None=None):self.toolchain=toolchain or SecurityToolchain();self.core=MatureEngineRunner()
 def inventory(self)->List[Dict[str,Any]]:
  base={x["name"]:x for x in self.toolchain.inventory()}
  for name,policy in ENGINE_POLICY.items():
   if name not in base:
    binary=policy.get("binary");base[name]={"name":name,"binary":shutil.which(binary) if binary else None,"available":bool(binary and shutil.which(binary)),"kind":"verification-service" if name=="sourcify" else "external-engine","license":"service/protocol; no local binary","project":"ethereum/sourcify" if name=="sourcify" else "unknown"}
  for name,meta in self.core.inventory().items():base[name]={**base.get(name,{}),"name":name,"binary":meta["binary"],"available":meta["available"],"path":meta["path"],"license":meta["license"],"project":meta["project"]}
  return list(base.values())
 def _run(self,command:List[str],cwd:str,timeout:int)->Dict[str,Any]:
  bounded=max(1,min(int(timeout),180));started=time.monotonic()
  try:
   p=subprocess.run(command,cwd=cwd,text=True,capture_output=True,timeout=bounded);out=p.stdout or "";err=p.stderr or "";return {"status":"completed" if p.returncode==0 else "failed","returncode":p.returncode,"stdout":out[-30000:],"stderr":err[-15000:],"stdout_sha256":hashlib.sha256(out.encode("utf-8","replace")).hexdigest(),"stderr_sha256":hashlib.sha256(err.encode("utf-8","replace")).hexdigest(),"command":command,"cwd":os.path.abspath(cwd),"duration_seconds":round(time.monotonic()-started,3)}
  except FileNotFoundError:return {"status":"not_available","error":f"tool not installed: {command[0]}","command":command,"cwd":os.path.abspath(cwd)}
  except subprocess.TimeoutExpired as exc:
   out=exc.stdout or "";err=exc.stderr or "";out=out.decode("utf-8","replace") if isinstance(out,bytes) else out;err=err.decode("utf-8","replace") if isinstance(err,bytes) else err;return {"status":"timeout","error":f"tool exceeded {bounded}s limit","stdout":out[-30000:],"stderr":err[-15000:],"stdout_sha256":hashlib.sha256(out.encode("utf-8","replace")).hexdigest(),"stderr_sha256":hashlib.sha256(err.encode("utf-8","replace")).hexdigest(),"command":command,"cwd":os.path.abspath(cwd),"duration_seconds":bounded}
  except OSError as exc:return {"status":"failed","error":str(exc),"command":command,"cwd":os.path.abspath(cwd)}
 def _version(self,name,cwd):
  binary=ENGINE_POLICY.get(name,{}).get("binary") or name
  if not shutil.which(binary):return None
  r=self._run([binary,"--version"],cwd,15);text=(r.get("stdout","")+"\n"+r.get("stderr","")).strip();return text.splitlines()[0][:500] if text else None
 @staticmethod
 def _specialized_findings(name,result):
  out=result.get("stdout","")
  try:obj=json.loads(out)
  except (TypeError,ValueError):obj=None
  findings=[]
  if name=="osv-scanner" and isinstance(obj,dict):
   for source in obj.get("results",[]) if isinstance(obj.get("results"),list) else []:
    src=(source.get("source") or {}).get("path","")
    for pkg in source.get("packages",[]) if isinstance(source.get("packages"),list) else []:
     p=pkg.get("package") or {}
     for vuln in pkg.get("vulnerabilities",[]) or []:
      if isinstance(vuln,dict):findings.append({"id":vuln.get("id") or "OSV finding","title":vuln.get("id") or "Known dependency vulnerability","description":vuln.get("summary") or vuln.get("details") or "Known dependency vulnerability","severity":"high" if any(str(a).startswith("CVE-") for a in vuln.get("aliases",[])) else "medium","confidence":.95,"file":src,"location":src,"evidence":{"package":p,"vulnerability":vuln},"category":"dependency_vulnerability"})
  elif name=="gitleaks":
   for d in obj if isinstance(obj,list) else []:
    if isinstance(d,dict):
     file=d.get("File") or d.get("file") or "";line=d.get("StartLine") or d.get("startLine") or d.get("Line");findings.append({"id":d.get("RuleID") or d.get("ruleID") or "gitleaks-secret","title":d.get("Description") or d.get("description") or "Potential secret","description":d.get("Description") or d.get("description") or "Gitleaks secret detection","severity":"high","confidence":.9,"file":file,"line":line,"location":f"{file}:{line}" if file and line else file,"evidence":d,"category":"secret_exposure"})
  return findings
 def _selected(self,question:str,stage:int,available:Dict[str,Dict[str,Any]],explicit:Iterable[str]|None=None)->List[str]:
  allowed=set(explicit) if explicit else QUESTION_MAP.get(question,{"slither","forge"});return [n for n in allowed if ENGINE_POLICY.get(n,{}).get("stage")==stage and available.get(n,{}).get("available")]
 def run_stage1(self,source_dir:str,timeout:int=120,explicit:Iterable[str]|None=None)->Dict[str,Any]:
  inventory={x["name"]:x for x in self.inventory()};selected=[n for n in (explicit or ("slither","forge","osv-scanner","gitleaks")) if inventory.get(n,{}).get("available")];results=[]
  for name in selected:
   if name=="slither":core=self.core.run_slither(source_dir,timeout);results.append({"tool":name,"stage":1,"question":"broad","result":core.get("execution",{}),"findings":core.get("findings",[]),"integration":core,"review_status":STATUS});continue
   if name=="forge":core=self.core.run_foundry(source_dir,timeout);results.append({"tool":name,"stage":1,"question":"baseline","result":core.get("execution",{}),"findings":core.get("findings",[]),"integration":core,"review_status":STATUS});continue
   command=["osv-scanner","scan","source","-r",".","--format","json"] if name=="osv-scanner" else ["gitleaks","detect","--no-banner","--report-format","json","--report-path","-"];r=self._run(command,source_dir,timeout);findings=self._specialized_findings(name,r);results.append({"tool":name,"stage":1,"question":"dependencies" if name=="osv-scanner" else "secrets","result":r,"version":self._version(name,source_dir),"findings":findings,"evidence_provenance":{"engine":name,"version":self._version(name,source_dir),"command":r.get("command"),"cwd":r.get("cwd"),"stdout_sha256":r.get("stdout_sha256"),"stderr_sha256":r.get("stderr_sha256")},"review_status":STATUS})
  return {"stage":1,"selected":selected,"skipped":[n for n in (explicit or ("slither","forge","osv-scanner","gitleaks")) if n not in selected],"results":results,"resource_policy":{"timeout_seconds":min(int(timeout),180),"max_parallel":1}}
 def _score_engine(self,name,finding:Dict[str,Any],question:str,reachability:float=0.5,evidence:float=0.5)->float:
  p=ENGINE_POLICY[name];text=" ".join(str(finding.get(k,"")) for k in ("title","description","category")).lower();score=0.0
  score+=2.0 if question in p["questions"] else 0.0;score+=1.5*reachability;score+=1.5*evidence
  if name=="ityfuzz" and any(x in text for x in ("reentr","oracle","state","accounting")):score+=2
  if name=="halmos" and any(x in text for x in ("access","state","invariant","symbolic")):score+=2
  if name in {"medusa","echidna"} and any(x in text for x in ("invariant","state","fuzz")):score+=1
  return score
 def run_for_candidates(self,source_dir:str,findings:List[Dict[str,Any]],timeout:int=180)->Dict[str,Any]:
  inventory={x["name"]:x for x in self.inventory()};candidates=sorted(findings or [],key=lambda f:float(f.get("priority",f.get("priority_score",0)) or 0),reverse=True)[:10];decisions=[]
  for finding in candidates:
   question=self._question_for_finding(finding);reachability=float(finding.get("reachability",finding.get("reachability_score",0.5)) or 0.5);evidence=float(finding.get("confidence",finding.get("evidence_score",0.5)) or 0.5);eligible=[n for n in QUESTION_MAP.get(question,set()) if ENGINE_POLICY.get(n,{}).get("stage",9)>1 and inventory.get(n,{}).get("available")];ranked=sorted(eligible,key=lambda n:self._score_engine(n,finding,question,reachability,evidence),reverse=True);chosen=ranked[:1];evidence_runs=[]
   for name in chosen:
    if name=="halmos":result=self.core.run_halmos(source_dir,min(int(timeout),180))
    elif name=="ityfuzz":result=self.core.run_ityfuzz(source_dir,min(int(timeout),180))
    else:
     command={"medusa":["medusa","fuzz"],"echidna":["echidna-test","."],"wake":["wake","detect"]}.get(name)
     if not command:continue
     result=self._run(command,source_dir,min(int(timeout),180))
    evidence_runs.append({"tool":name,"stage":ENGINE_POLICY[name]["stage"],"question":question,"result":result,"review_status":STATUS})
   decisions.append({"finding_id":finding.get("id"),"question":question,"reachability_score":reachability,"evidence_score":evidence,"ranked_engines":ranked,"selected_engines":chosen,"selection_reason":"finding class + reachability + evidence confidence + tool specialization + bounded cost; one heavyweight escalation per candidate","evidence":evidence_runs,"review_status":STATUS})
  return {"stage":2,"decisions":decisions,"resource_policy":{"max_heavy_engines_per_candidate":1,"timeout_seconds":min(int(timeout),180)}}
 def _question_for_finding(self,finding:Dict[str,Any])->str:
  text=" ".join(str(finding.get(k,"")) for k in ("title","description","category")).lower()
  if any(x in text for x in ("reentr","callback")):return "reentrancy"
  if any(x in text for x in ("state machine","state transition","invariant")):return "state_machine"
  if any(x in text for x in ("oracle","price manipulation")):return "oracle"
  if any(x in text for x in ("accounting","rounding","precision","fee")):return "accounting"
  if any(x in text for x in ("access control","privilege","authorization")):return "access_control"
  if any(x in text for x in ("delegatecall","upgrade","proxy")):return "delegatecall"
  return "execution_path"
 def orchestrate(self,source_dir:str,findings:List[Dict[str,Any]]|None=None,timeout:int=120,explicit:Iterable[str]|None=None)->Dict[str,Any]:
  if not os.path.isdir(source_dir):return {"status":"error","reason":"source directory does not exist","review_status":STATUS}
  build=self.toolchain.detect_build(source_dir);stage1=self.run_stage1(source_dir,timeout,explicit);candidate_input=findings or [f for r in stage1["results"] for f in r.get("findings",[])];stage2=self.run_for_candidates(source_dir,candidate_input,min(timeout,180)) if candidate_input else {"stage":2,"decisions":[],"skipped":"no credible candidates"}
  return {"status":"orchestration_complete","build":build,"inventory":self.inventory(),"stage1":stage1,"stage2":stage2,"stage3":{"status":"deferred","reason":"deep engines require a high-value candidate and explicit escalation"},"findings_are_evidence_only":True,"review_status":STATUS}
