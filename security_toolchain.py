"""Safe adapters for locally installed open-source security tools.

Adapters never install tools, access networks, or test a target by themselves.
Callers must establish explicit bounty authorization first. Commands are bounded
and execute only against a supplied local checkout.
"""
from __future__ import annotations
import os, shutil, subprocess
from typing import Any, Dict, List, Optional

TOOLS = {
    "slither": {"binary":"slither","kind":"static","license":"AGPL-3.0-or-later","project":"crytic/slither"},
    "aderyn": {"binary":"aderyn","kind":"static","license":"GPL-3.0","project":"Cyfrin/aderyn"},
    "forge": {"binary":"forge","kind":"build-fuzz-test","license":"Apache-2.0 OR MIT","project":"foundry-rs/foundry"},
    "echidna": {"binary":"echidna-test","kind":"property-fuzz","license":"AGPL-3.0","project":"crytic/echidna"},
    "medusa": {"binary":"medusa","kind":"coverage-guided-fuzz","license":"AGPL-3.0","project":"crytic/medusa"},
    "wake": {"binary":"wake","kind":"static-fuzz-framework","license":"ISC","project":"Ackee-Blockchain/wake"},
}

class SecurityToolchain:
    def inventory(self) -> List[Dict[str,Any]]:
        return [{"name":n,"available":bool((p:=shutil.which(m['binary']))),"binary":p,"kind":m['kind'],"license":m['license'],"project":m['project']} for n,m in TOOLS.items()]
    def _run(self,command:List[str],cwd:str,timeout:int)->Dict[str,Any]:
        if not os.path.isdir(cwd): return {"ok":False,"error":"source directory does not exist"}
        try:
            p=subprocess.run(command,cwd=cwd,text=True,capture_output=True,timeout=max(1,min(timeout,300)))
            return {"ok":p.returncode==0,"returncode":p.returncode,"stdout":p.stdout[-20000:],"stderr":p.stderr[-10000:]}
        except FileNotFoundError:return {"ok":False,"error":f"tool not installed: {command[0]}"}
        except subprocess.TimeoutExpired:return {"ok":False,"error":"tool timed out"}
    def analyze(self,source_dir:str,tools:Optional[List[str]]=None,timeout:int=120)->Dict[str,Any]:
        requested=tools or ["slither","aderyn","wake"]
        results=[]
        for name in requested:
            meta=TOOLS.get(name)
            if not meta: results.append({"name":name,"ok":False,"error":"unsupported tool"}); continue
            if not shutil.which(meta['binary']): results.append({"name":name,"ok":False,"skipped":True,"error":"not installed","license":meta['license'],"project":meta['project']}); continue
            if name=='slither': cmd=[meta['binary'],'.','--json','-']
            elif name=='aderyn': cmd=[meta['binary'],'--output','-','.']
            elif name=='wake': cmd=[meta['binary'],'detect']
            elif name=='forge': cmd=[meta['binary'],'test','--json']
            elif name=='medusa': cmd=[meta['binary'],'fuzz','--help']
            else: cmd=[meta['binary'],'--help']
            results.append({"name":name,"license":meta['license'],"project":meta['project'],"result":self._run(cmd,source_dir,timeout)})
        return {"authorized_local_analysis_only":True,"results":results}
