#!/usr/bin/env python3
"""Local-only real-target validation with backend-authoritative target authorization."""
from __future__ import annotations
import json, os, shutil, subprocess, tempfile, sys
from pathlib import Path
from urllib.request import Request, urlopen
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from authorization import AuthorizationPolicy
from bounty_engine import Opportunity, score_opportunity
from research_pipeline import ResearchPipeline, STATUS
SCOPE_URL="https://immunefi.com/bug-bounty/0x/scope/"
INFO_URL="https://immunefi.com/bug-bounty/0x/information/"
REPO_URL="https://github.com/0xProject/0x-settler.git"
def fetch(url):
    req=Request(url,headers={"User-Agent":"Web3-BugHunter/real-target-smoke"})
    with urlopen(req,timeout=30) as r:return r.read().decode("utf-8","replace")
def run(cmd,cwd=None,timeout=1200):
    p=subprocess.run(cmd,cwd=cwd,text=True,capture_output=True,timeout=timeout)
    return {"returncode":p.returncode,"stdout":p.stdout[-16000:],"stderr":p.stderr[-12000:]}
def main():
    scope,info=fetch(SCOPE_URL),fetch(INFO_URL)
    required=["0x Settler","test-nets are not in scope"]
    if not all(x.lower() in scope.lower() for x in required):raise RuntimeError("0x scope evidence could not be verified")
    opp=Opportunity(id="immunefi:0x",source="immunefi",name="0x",url=INFO_URL,status="active",max_bounty_usd=1000000,scope_size=6,source_code_available=True,competition_risk=.85,difficulty=.72,estimated_hours=36,severity_potential=1.0,likelihood=.55,attack_surface=["Settler","AllowanceHolder","ERC2771 forwarding","cross-chain receiver","Pauser Safe module"],scope_notes="Published Immunefi scope explicitly identifies 0x Settler source tree and named deployed assets; testnets are excluded. Local source analysis only.",metadata={"repositories":["https://github.com/0xProject/0x-settler"],"scope_url":SCOPE_URL,"rules_url":INFO_URL,"eligible_source":"https://github.com/0xProject/0x-settler/tree/master/src"})
    opp.score=score_opportunity(opp)
    opp_dict=opp.to_dict()
    authorization=AuthorizationPolicy.status(opp_dict,[])
    with tempfile.TemporaryDirectory(prefix="web3-bughunter-0x-") as td:
      repo=Path(td)/"0x-settler";clone=run(["git","clone","--depth","1","--branch","master",REPO_URL,str(repo)],timeout=300)
      if clone["returncode"]:raise RuntimeError(json.dumps({"stage":"acquisition","result":clone}))
      build={"forge_build":run(["forge","build"],cwd=repo,timeout=1200) if shutil.which("forge") else {"skipped":"forge not installed"}}
      target_allowed,target_reason=AuthorizationPolicy.target_allowed(opp_dict,{"source_url":REPO_URL,"source_dir":str(repo)})
      result={"status":"blocked","reason":target_reason,"authorization":authorization,"target_authorization_allowed":target_allowed,"findings":[]}
      if target_allowed:
        parts=[];root=repo/"src"
        for p in root.rglob("*.sol") if root.is_dir() else []:
          try:parts.append(f"// FILE: {p.relative_to(repo)}\n{p.read_text(encoding='utf-8',errors='replace')}")
          except OSError:pass
        result=ResearchPipeline().analyze_local(str(repo),"0x Settler",source_code="\n\n".join(parts),authorization_confirmed=True,tools=["slither","aderyn","wake"],opportunity=opp_dict)
      out={"opportunity":opp_dict,"public_scope_verified":True,"scope_url":SCOPE_URL,"rules_url":INFO_URL,"repository":REPO_URL,"acquisition":{"ok":True,"revision":"master"},"build":build,"authorization":authorization,"target_authorization_allowed":target_allowed,"target_authorization_reason":target_reason,"pipeline":result,"finding_status":STATUS}
      Path("real_target_0x_result.json").write_text(json.dumps(out,indent=2,default=str),encoding="utf-8")
      print(json.dumps({"program":"0x","score":opp.score,"target_authorization_allowed":target_allowed,"analysis_status":result.get("status"),"finding_count":len(result.get("correlated_findings",[])),"review_status":STATUS},indent=2))
if __name__=="__main__":main()
