#!/usr/bin/env python3
"""Existing Web3 BugHunter analyzer, preserved as the core code-analysis engine."""
from flask import Flask
import anthropic, os, re
from dataclasses import dataclass

app=Flask(__name__)
client=anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY")) if os.environ.get("ANTHROPIC_API_KEY") else None

@dataclass
class Finding:
 id:str; vulnerability_type:str; severity:str; category:str; location:str; description:str; proof_of_concept:str; economic_impact:str; likelihood_score:float; bounty_estimate_low:int; bounty_estimate_high:int; confidence:float; requires_verification:bool; learning_value:str

class AdvancedWeb3Analyzer:
 def __init__(self): self.findings=[]; self.protocol_knowledge={}; self.exploit_patterns=[]
 def analyze_protocol(self,code,protocol_name,network="ethereum"):
  findings=self._specialized(code)+self._legacy_signals(code)
  out={}
  for f in findings:
   key=(f.category,f.location)
   if key not in out or f.confidence>out[key].confidence: out[key]=f
  return list(out.values())
 def _finding(self,key,name,severity,category,code,pos,desc,evidence,impact="Source-derived impact requires local reproduction.",confidence=.75):
  return Finding(f"{key}_{len(self.findings)}",name,severity,category,f"Source evidence near line {self._line(code,pos)}",desc,evidence[:1000],impact,confidence,self._low(severity),self._high(severity,confidence),confidence,True,"Validate the complete attacker path and security invariant locally.")
 def _specialized(self,code):
  fs=[]
  # Signature/replay: ecrecover-based state mutation without freshness/consumption.
  if re.search(r'\becrecover\s*\(',code,re.I):
   for m in re.finditer(r'function\s+(\w+)\s*\([^)]*\b(?:bytes32|bytes)\b[^)]*\)[^{]*\{(?P<body>.*?)\}',code,re.I|re.S):
    body=m.group('body')
    if re.search(r'\b(?:claim|permit|execute|withdraw|mint|approve|transfer)\w*\b',m.group(1),re.I) and not re.search(r'\b(?:nonce|used|deadline|chainId|domainSeparator)\b',body,re.I):
     fs.append(self._finding('signature_replay','Signature replay / missing authorization freshness','high','signature',code,m.start(),'A state-changing signature flow uses a caller-supplied digest but shows no nonce, consumed-digest, deadline, or domain-separation guard in the local function.',body))
     fs.append(self._finding('replay','Replay protection missing from signature authorization','high','replay',code,m.start(),'The signed authorization appears reusable because no consumed nonce/digest or expiry is checked before the state mutation.',body))
  # Initialization takeover.
  for m in re.finditer(r'function\s+(initialize|init|reinitialize)\s*\([^)]*\)[^{]*\{(?P<body>.*?)\}',code,re.I|re.S):
   body=m.group('body')
   if re.search(r'\b(?:owner|admin|implementation|pendingOwner)\b\s*=',body,re.I) and not re.search(r'\b(?:initialized|onlyOwner|initializer|reinitializer)\b',body,re.I):
    fs += [self._finding('initialization','Unprotected initializer / initialization takeover','critical','initialization',code,m.start(),'Initialization writes a privileged control variable without an observed one-time or authorization guard.',body),self._finding('init_upgrade','Initialization exposes upgrade/privilege boundary','high','upgrade',code,m.start(),'The initializer controls an upgrade-relevant privileged variable and lacks an observed initialization guard.',body),self._finding('init_privilege','Initialization privilege escalation','critical','privilege',code,m.start(),'A public initializer assigns privileged ownership/admin state without an observed authorization or one-time guard.',body)]
  # Reentrancy: callback before relevant state write, unless a local guard is present.
  for m in re.finditer(r'function\s+(\w+)\s*\([^)]*\)[^{]*\{(?P<body>.*?)\}',code,re.I|re.S):
   body=m.group('body'); call=re.search(r'\.(?:call|send|transfer)\s*(?:\{|\()',body,re.I)
   if call and not re.search(r'\bnonReentrant\b|locked\s*=\s*true',body,re.I):
    after=body[call.end():]
    if re.search(r'\b(?:balance|balances|shares|debt|state|status)\w*\s*(?:=|\+=|-=)',after,re.I):
     fs.append(self._finding('reentrancy','Reentrancy: external callback precedes state update','critical','reentrancy',code,m.start(),'An external/value callback occurs before a relevant state write in the same callable path and no obvious local reentrancy guard is present.',body))
  # Sensitive operations without an observed authorization check.
  sensitive=r'\b(?:upgrade|mint|burn|pause|set[A-Z]\w*|sweep|withdrawAll|transferOwnership)\w*\b'
  for m in re.finditer(r'function\s+(\w+)\s*\([^)]*\)(?P<head>[^\{;]*)\{(?P<body>.*?)\}',code,re.I|re.S):
   name,head,body=m.group(1),m.group('head'),m.group('body')
   if re.search(sensitive,name,re.I) and re.search(r'\b(?:owner|admin|role|implementation|balance|totalSupply)\w*\s*(?:=|\+=|-=)',body,re.I) and not re.search(r'\b(?:onlyOwner|onlyRole|hasRole|require\s*\(\s*msg\.sender\s*==|_authorizeUpgrade)\b',head+' '+body,re.I):
    fs += [self._finding('access_control','Sensitive state mutation lacks an observed authorization guard','high','access_control',code,m.start(),'A sensitive externally callable operation mutates privileged or value-bearing state without an observed role/owner authorization check.',body),self._finding('privilege','Privilege escalation path','high','privilege',code,m.start(),'An attacker-controlled caller appears able to reach a privileged mutation without a visible authorization invariant.',body)]
  return fs
 def _legacy_signals(self,code):
  specs=[('state_manipulation','State Machine Manipulation','critical','business_logic',[r'\b(?:state|status)\s*=',r'\b(?:transition|nextState)\b']),('oracle','Oracle Manipulation / Price Attack','critical','oracle_attack',[r'\b(?:oracle|chainlink|latestAnswer|latestRoundData|getPrice|priceFeed|twap|spotPrice)\b']),('flash','Flash Loan Attack Vector','critical','flash_loan',[r'\b(?:flashLoan|flashSwap)\b']),('delegatecall','Unsafe delegatecall / upgrade surface','high','delegatecall',[r'\.(?:delegatecall|callcode)\s*\(']),('precision','Precision / rounding risk','medium','precision',[r'\b(?:mulDiv|decimals|round|1e\d+|10\s*\*\*|/\s*\d+)\b']),('accounting','Accounting invariant risk','high','accounting',[r'\b(?:totalAssets|totalSupply|shares|debt|reserve)\w*\s*(?:\+=|-=|=)'])]
  fs=[]
  for key,name,sev,cat,pats in specs:
   for p in pats:
    m=re.search(p,code,re.I)
    if m: fs.append(self._finding(key,name,sev,cat,code,m.start(),'Source-level signal requiring an end-to-end attacker-path check.',code[max(0,m.start()-180):min(len(code),m.end()+300)],'Impact is not quantified until local reproduction establishes affected value.',.62))
  return fs
 def _line(self,code,pos): return code[:pos].count('\n')+1
 def _low(self,severity): return {'critical':5000,'high':1000,'medium':500,'low':100}.get(severity,100)
 def _high(self,severity,confidence): return int({'critical':50000,'high':10000,'medium':5000,'low':1000}.get(severity,1000)*(.5+confidence))
 def fuzz_contract(self,contract_abi,contract_address): return []
 def analyze_economics(self,protocol_params): return []

def generate_detailed_report(finding):
 if client is None:
  return f"# {finding.vulnerability_type}\n\n**Status:** UNVERIFIED — HUMAN REVIEW REQUIRED\n\n## Severity\n{finding.severity.upper()}\n\n## Affected Location\n{finding.location}\n\n## Description\n{finding.description}\n\n## Evidence / PoC\n{finding.proof_of_concept}\n\n## Potential Impact\n{finding.economic_impact}\n\n## Confidence\n{finding.confidence*100:.0f}%\n\n## Human Verification\nReproduce in an explicitly authorized environment and confirm scope, impact, and duplicate status.\n\n## Remediation\nApply protocol-specific controls after confirming the root cause.\n\n## Submission Gate\nNever auto-submit; human approval is required."
 prompt=f"Create a professional Web3 security report for {finding.vulnerability_type}. Severity {finding.severity}; location {finding.location}; description {finding.description}; evidence {finding.proof_of_concept}; impact {finding.economic_impact}. Include executive summary, technical explanation, reproduction/PoC, impact, verification steps, remediation, and learning points. Clearly label UNVERIFIED — HUMAN REVIEW REQUIRED and never suggest automatic submission."
 return client.messages.create(model=os.environ.get('ANTHROPIC_MODEL','claude-opus-4-1'),max_tokens=3000,messages=[{'role':'user','content':prompt}]).content[0].text
