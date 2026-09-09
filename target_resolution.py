"""Deterministic scope parsing and local project/build detection.

This module only resolves information already supplied by public program evidence or
local source trees. It never treats discovery as authorization and never probes live
contracts or chains.
"""
from __future__ import annotations
import json,re
from pathlib import Path
from typing import Any,Dict,List
from urllib.parse import urljoin,urlparse

ADDRESS_RE=re.compile(r"\b0x[a-fA-F0-9]{40}\b")
GITHUB_RE=re.compile(r"https?://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?")
EVM_ADDRESS_LABEL=re.compile(r"(?:address|contract|deployment|token|asset)[^\n]{0,120}?\b(0x[a-fA-F0-9]{40})\b",re.I)

class ScopeResolver:
    """Turn heterogeneous program metadata/evidence into auditable target records."""
    def resolve(self, opportunity:Dict[str,Any], evidence:str="")->Dict[str,Any]:
        meta=opportunity.get('metadata') or {}; text='\n'.join([str(evidence or ''),str(opportunity.get('scope_notes','')),json.dumps(meta,default=str)])
        repos=[]
        for key in ('repositories','repository','repo','source_code','sourceCode','github','github_url'):
            value=meta.get(key)
            vals=value if isinstance(value,list) else [value] if value else []
            for v in vals:
                if isinstance(v,str): repos += GITHUB_RE.findall(v)
        repos += GITHUB_RE.findall(text)
        repos=list(dict.fromkeys(r.rstrip('.,);]').removesuffix('.git') for r in repos))
        addresses=list(dict.fromkeys(ADDRESS_RE.findall(text)))
        assets=meta.get('assets') or meta.get('assetsInScope') or []
        exclusions=meta.get('out_of_scope') or meta.get('outOfScopeImpacts') or meta.get('exclusions') or []
        rules=meta.get('rules') or meta.get('scope_rules') or ''
        targets=[]
        for repo in repos: targets.append({'kind':'repository','identifier':repo,'source_url':repo,'explicitly_published':True,'authorization_required':True})
        for address in addresses: targets.append({'kind':'evm_contract','identifier':address,'address':address,'explicitly_published':True,'authorization_required':True})
        return {'opportunity_id':opportunity.get('id'),'program':opportunity.get('name'),'source':opportunity.get('source'),'program_url':opportunity.get('url'),'targets':targets,'repositories':repos,'contract_addresses':addresses,'assets':assets if isinstance(assets,list) else [assets],'exclusions':exclusions if isinstance(exclusions,list) else [exclusions],'rules':rules,'scope_evidence':evidence,'authorization_required':True,'authorization_confirmed':bool(opportunity.get('authorization_confirmed'))}

class BuildDetector:
    MARKERS={
      'foundry':('foundry.toml','lib/forge-std','script/'),
      'hardhat':('hardhat.config.js','hardhat.config.ts','hardhat.config.cjs','hardhat.config.mjs'),
      'brownie':('brownie-config.yaml','brownie-config.yml','brownie-config.py'),
      'truffle':('truffle-config.js','truffle-config.ts','truffle.js'),
      'ape':('ape-config.yaml','ape-config.yml'),
      'dapp':('Dappfile',),
    }
    def detect(self,source_dir:str)->Dict[str,Any]:
        root=Path(source_dir)
        if not root.is_dir(): return {'detected':[],'primary':None,'error':'source directory does not exist'}
        hits=[]
        for system,markers in self.MARKERS.items():
            evidence=[m for m in markers if (root/m).exists()]
            if evidence: hits.append({'system':system,'evidence':evidence})
        if (root/'package.json').exists():
            try:
                pkg=json.loads((root/'package.json').read_text(encoding='utf-8'))
                deps={**pkg.get('dependencies',{}),**pkg.get('devDependencies',{})}
                for name,system in [('hardhat','hardhat'),('@nomicfoundation/hardhat-toolbox','hardhat'),('truffle','truffle'),('@brownie','brownie')]:
                    if any(name.lower() in str(k).lower() for k in deps):
                        if not any(x['system']==system for x in hits): hits.append({'system':system,'evidence':['package.json']})
            except (OSError,ValueError): pass
        primary=hits[0]['system'] if hits else ('solidity-generic' if list(root.rglob('*.sol'))[:1] else None)
        return {'detected':hits,'primary':primary,'solidity_files':len(list(root.rglob('*.sol'))),'authorization_required':True}

class TargetMap:
    def build(self,scope:Dict[str,Any],build_info:Dict[str,Any])->Dict[str,Any]:
        return {'program':scope.get('program'),'targets':scope.get('targets',[]),'repositories':scope.get('repositories',[]),'contracts':scope.get('contract_addresses',[]),'assets':scope.get('assets',[]),'exclusions':scope.get('exclusions',[]),'rules':scope.get('rules'),'build':build_info,'complete_map':True,'authorization_required':True}
