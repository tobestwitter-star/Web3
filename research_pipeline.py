"""Target acquisition and research orchestration for Web3 BugHunter.

Network acquisition is restricted to explicitly supplied public source URLs and Git
repositories. Active security testing is blocked unless authorization is explicitly
confirmed by the caller. The module is deterministic/offline-testable and does not
bypass authentication, anti-bot controls, or rate limits.
"""
from __future__ import annotations
import hashlib, json, os, re, shutil, subprocess, tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from advanced_web3_analyzer import AdvancedWeb3Analyzer
from security_toolchain import SecurityToolchain

@dataclass
class Target:
    name: str
    source_url: str
    kind: str = "repository"
    branch: str = ""
    authorized: bool = False
    scope_evidence: str = ""
    addresses: List[str] = None
    contracts: List[str] = None
    assets: List[str] = None
    def to_dict(self):
        d=asdict(self); d["addresses"]=d["addresses"] or []; d["contracts"]=d["contracts"] or []; d["assets"]=d["assets"] or []; return d

class TargetAcquirer:
    GIT_RE=re.compile(r"https?://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?(?:/tree/[^\s#]+)?")
    ADDRESS_RE=re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    def _allowed_url(self,url):
        p=urlparse(url); return p.scheme in ("http","https") and p.netloc
    def extract_targets(self, opportunity: Dict[str,Any], public_text: str = "") -> List[Target]:
        """Extract only explicit public source/repository references from program evidence."""
        meta=opportunity.get("metadata") or {}; candidates=[]
        for key in ("repositories","repository","repo","source_code","sourceCode","github","github_url"):
            v=meta.get(key)
            if isinstance(v,str): candidates.append(v)
            elif isinstance(v,list): candidates.extend(str(x) for x in v)
        candidates += self.GIT_RE.findall(public_text or "")
        seen=set(); targets=[]
        for url in candidates:
            url=url.rstrip(".,);]")
            if not self._allowed_url(url) or "github.com/" not in url: continue
            base=url.split("/tree/")[0].removesuffix(".git")
            if base in seen: continue
            seen.add(base)
            addresses=self.ADDRESS_RE.findall(public_text or "")
            targets.append(Target(opportunity.get("name","target"),base,"repository",authorized=False,scope_evidence="Public reference extracted; authorization still requires explicit human scope confirmation.",addresses=addresses))
        return targets

    def clone_public_repo(self,target: Target, workspace: str, authorization_confirmed: bool=False) -> Dict[str,Any]:
        if not authorization_confirmed or not target.authorized:
            return {"ok":False,"blocked":"authorization_required","reason":"Repository acquisition for research requires explicit scope confirmation."}
        if not target.source_url.startswith(("https://github.com/","http://github.com/")):
            return {"ok":False,"error":"only public GitHub repositories are supported by this safe adapter"}
        Path(workspace).mkdir(parents=True,exist_ok=True); dest=os.path.join(workspace,hashlib.sha256(target.source_url.encode()).hexdigest()[:12])
        if os.path.exists(dest): return {"ok":True,"path":dest,"cached":True}
        try:
            p=subprocess.run(["git","clone","--depth","1",target.source_url,dest],capture_output=True,text=True,timeout=180)
            return {"ok":p.returncode==0,"path":dest if p.returncode==0 else None,"stdout":p.stdout[-4000:],"stderr":p.stderr[-6000:]}
        except (FileNotFoundError,subprocess.TimeoutExpired) as e: return {"ok":False,"error":str(e)}

class FindingCorrelator:
    SEVERITY={"critical":4,"high":3,"medium":2,"low":1,"informational":0}
    def normalize(self, finding: Dict[str,Any], engine: str) -> Dict[str,Any]:
        text=" ".join(str(finding.get(k,'')) for k in ('title','vulnerability','description','message','check'))
        loc=str(finding.get('location') or finding.get('path') or finding.get('source') or '')
        sev=str(finding.get('severity') or 'medium').lower()
        return {"engine":engine,"title":finding.get('title') or finding.get('vulnerability') or finding.get('check') or engine,"description":text[:4000],"location":loc,"severity":sev,"confidence":float(finding.get('confidence',.45) or .45),"fingerprint":hashlib.sha256((re.sub(r'\s+',' ',text.lower())+'|'+loc.lower()).encode()).hexdigest()}
    def correlate(self, groups: Iterable[Dict[str,Any]]) -> List[Dict[str,Any]]:
        merged={}
        for g in groups:
            engine=g.get('engine','unknown')
            findings=g.get('findings') or []
            for raw in findings:
                f=self.normalize(raw,engine); key=f['fingerprint'][:20]
                if key not in merged: merged[key]={**f,'engines':[engine],'occurrences':1,'cross_tool_confidence':f['confidence']}
                else:
                    m=merged[key]; m['occurrences']+=1
                    if engine not in m['engines']: m['engines'].append(engine)
                    m['cross_tool_confidence']=min(1,max(m['cross_tool_confidence'],f['confidence'])+.12)
                    if self.SEVERITY.get(f['severity'],2)>self.SEVERITY.get(m['severity'],2): m['severity']=f['severity']
        for f in merged.values():
            f['validated_by_multiple_tools']=len(f['engines'])>=2
            f['status']='UNVERIFIED — HUMAN REVIEW REQUIRED'
            f['priority']=round(self.SEVERITY.get(f['severity'],2)*25 + min(25,f['cross_tool_confidence']*25) + (10 if f['validated_by_multiple_tools'] else 0),2)
        return sorted(merged.values(),key=lambda x:x['priority'],reverse=True)

class ResearchPipeline:
    def __init__(self): self.acquirer=TargetAcquirer(); self.tools=SecurityToolchain(); self.correlator=FindingCorrelator()
    def plan(self, opportunity: Dict[str,Any], public_evidence: str = "") -> Dict[str,Any]:
        targets=self.acquirer.extract_targets(opportunity,public_evidence)
        available=self.tools.inventory()
        return {"opportunity":opportunity,"targets":[t.to_dict() for t in targets],"tools":available,"authorization_required":True,"active_testing_allowed":False if not opportunity.get('authorization_confirmed') else True}
    def analyze_local(self, source_dir: str, protocol_name: str, source_code: Optional[str]=None, authorization_confirmed: bool=False, tools: Optional[List[str]]=None) -> Dict[str,Any]:
        if not authorization_confirmed:
            return {"status":"blocked","reason":"Explicit authorization confirmation is required before analysis/testing.","findings":[]}
        groups=[]
        if source_code:
            try:
                fs=AdvancedWeb3Analyzer().analyze_protocol(source_code,protocol_name)
                groups.append({"engine":"existing_analyzer","findings":[{"title":f.vulnerability_type,"severity":f.severity,"description":f.description,"location":f.location,"confidence":f.confidence} for f in fs]})
            except Exception as exc: groups.append({"engine":"existing_analyzer","findings":[],"error":str(exc)})
        tool_result=self.tools.analyze(source_dir,tools or ["slither","aderyn"],120)
        for r in tool_result.get('results',[]):
            rr=r.get('result') or {}; text=(rr.get('stdout') or '')+'\n'+(rr.get('stderr') or '')
            findings=[]
            # Preserve raw evidence while extracting conservative line/check leads.
            for line in text.splitlines():
                if any(x in line.lower() for x in ('warning','high','medium','low','reentr','access-control','unchecked')):
                    findings.append({'title':line[:240],'description':line[:1000],'severity':'high' if 'high' in line.lower() else 'medium' if 'medium' in line.lower() else 'low','confidence':.45})
            groups.append({'engine':r.get('name','tool'),'findings':findings})
        correlated=self.correlator.correlate(groups)
        return {"status":"analysis_complete","authorization_confirmed":True,"tool_results":tool_result,"correlated_findings":correlated,"review_status":"UNVERIFIED — HUMAN REVIEW REQUIRED"}
