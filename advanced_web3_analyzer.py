#!/usr/bin/env python3
"""Existing Web3 BugHunter analyzer, preserved as the core code-analysis engine."""
from flask import Flask
import anthropic, json, os, re
from dataclasses import dataclass
from typing import Optional, List, Dict

app=Flask(__name__)
client=anthropic.Anthropic(api_key=os.environ.get('ANTHROPIC_API_KEY')) if os.environ.get('ANTHROPIC_API_KEY') else None
ADVANCED_VULNERABILITIES={
'state_manipulation':{'name':'State Machine Manipulation','severity':'critical','category':'business_logic','patterns':[r'(state\s*=|status\s*=)',r'(require.*state|if.*state)',r'(transition|update.*state)'],'description':'Contract may allow invalid state transitions or inconsistent state changes','economic_impact':'Potential protocol fund loss','indicators':['State changes without validation','Missing current-state checks']},
'incentive_misalignment':{'name':'Incentive Misalignment / Game Theory Break','severity':'critical','category':'economic_attack','patterns':[r'(reward|fee|profit|incentive)',r'(totalSupply|balanceOf.*=)',r'(mint|burn|transfer).*amount'],'description':'Protocol incentives may permit profitable behavior that violates economic assumptions','economic_impact':'Potential direct attacker profit','indicators':['Rewards exceed value produced','Protocol-loss arbitrage']},
'reentrancy_complex':{'name':'Complex Reentrancy / Callback Attack','severity':'critical','category':'call_pattern','patterns':[r'\.call\{value:',r'\.delegatecall',r'(external|payable).*function',r'(balances\[|state\[).*=' ],'description':'External callbacks may permit reentrant state manipulation','economic_impact':'Potential direct fund theft','indicators':['External calls before state updates','Callback chains']},
'oracle_manipulation':{'name':'Oracle Manipulation / Price Attack','severity':'critical','category':'oracle_attack','patterns':[r'(getPrice|fetchPrice|oracle|chainlink|price\[)',r'(block\.timestamp|block\.number).*price',r'(latestRound|latestAnswer)'],'description':'Pricing assumptions may be manipulable','economic_impact':'Potential liquidation or collateral loss','indicators':['Single-source pricing','Insufficient manipulation resistance']},
'flash_loan_attack':{'name':'Flash Loan Attack Vector','severity':'critical','category':'flash_loan','patterns':[r'(flashLoan|borrow.*repay|flashSwap)',r'(balance.*before|balance.*after)'],'description':'Flash liquidity may amplify a state or accounting weakness','economic_impact':'Potential large single-transaction loss','indicators':['Borrowed capital can affect sensitive state','Weak balance/accounting checks']},
'front_running_advanced':{'name':'Advanced Front-Running / MEV Extraction','severity':'high','category':'mev_attack','patterns':[r'(pendingRewards|queue|order|pending)',r'(calculateFee|slippage|price.*=)'],'description':'Transaction ordering may permit value extraction','economic_impact':'Potential repeated MEV extraction','indicators':['Predictable ordering dependency','Insufficient slippage protection']},
'access_control_business_logic':{'name':'Broken Access Control (Business Logic)','severity':'high','category':'access_control','patterns':[r'(public|external)\s+function',r'(requires|require).*msg\.sender|admin'],'description':'Business-critical functions may lack appropriate authorization constraints','economic_impact':'Potential unauthorized privileged action','indicators':['Missing role checks','Weak delegation boundaries']},
'integer_arithmetic_complex':{'name':'Integer Arithmetic Edge Case','severity':'high','category':'arithmetic','patterns':[r'(\+|-|\*|/).*amount',r'(uint256|uint|int)\s+\w+.*=.*\+'],'description':'Arithmetic operations deserve boundary and precision review','economic_impact':'Potential accounting or fund loss','indicators':['Boundary-sensitive arithmetic','Precision or conversion risk']},
'dependency_injection':{'name':'Dangerous External Dependency','severity':'high','category':'external_call','patterns':[r'(delegatecall|callcode|\.call)',r'(external.*contract|interface.*external)'],'description':'External dependencies may expand the attack surface','economic_impact':'Potential behavior or fund impact','indicators':['Unverified external trust assumptions','Unsafe upgrade/call patterns']}}

@dataclass
class Finding:
 id:str; vulnerability_type:str; severity:str; category:str; location:str; description:str; proof_of_concept:str; economic_impact:str; likelihood_score:float; bounty_estimate_low:int; bounty_estimate_high:int; confidence:float; requires_verification:bool; learning_value:str

class AdvancedWeb3Analyzer:
 def __init__(self): self.findings=[]; self.protocol_knowledge={}; self.exploit_patterns=[]
 def analyze_protocol(self,code,protocol_name,network='ethereum'):
  findings=[]
  for key,data in ADVANCED_VULNERABILITIES.items():
   for pattern in data['patterns']:
    for match in re.finditer(pattern,code,re.MULTILINE|re.IGNORECASE):
     context=code[max(0,match.start()-200):min(len(code),match.end()+200)]; confidence=self._calculate_confidence(data['category'],context,protocol_name)
     if confidence>.5: findings.append(Finding(f'{key}_{len(findings)}',data['name'],data['severity'],data['category'],f'Pattern match near line {self._estimate_line_number(code,match.start())}',data['description'],context[:200]+'...',data['economic_impact'],confidence,self._estimate_bounty_low(data['severity']),self._estimate_bounty_high(data['severity'],confidence),confidence,True,self._generate_learning_value(data)))
  return findings
 def _calculate_confidence(self,category,context,protocol_name):
  base={'business_logic':.8,'economic_attack':.85,'call_pattern':.7,'oracle_attack':.75,'flash_loan':.8,'mev_attack':.7,'access_control':.65,'arithmetic':.6,'external_call':.7}.get(category,.5)
  if protocol_name.lower() in context.lower(): base+=.1
  if 'require' in context.lower() or 'revert' in context.lower(): base+=.05
  return min(1,base)
 def _estimate_line_number(self,code,position): return code[:position].count('\n')+1
 def _estimate_bounty_low(self,severity): return {'critical':5000,'high':1000,'medium':500,'low':100}.get(severity,100)
 def _estimate_bounty_high(self,severity,confidence): return int({'critical':50000,'high':10000,'medium':5000,'low':1000}.get(severity,1000)*(.5+confidence))
 def _generate_learning_value(self,data): return f"Study {data['name']}: {', '.join(data.get('indicators',[])[:2])}"
 def fuzz_contract(self,contract_abi,contract_address): return []
 def analyze_economics(self,protocol_params): return []

def generate_detailed_report(finding):
 if client is None:
  return f"# {finding.vulnerability_type}\n\n**Status:** UNVERIFIED — HUMAN REVIEW REQUIRED\n\n## Severity\n{finding.severity.upper()}\n\n## Affected Location\n{finding.location}\n\n## Description\n{finding.description}\n\n## Evidence / PoC\n{finding.proof_of_concept}\n\n## Potential Impact\n{finding.economic_impact}\n\n## Confidence\n{finding.confidence*100:.0f}%\n\n## Human Verification\nReproduce in an explicitly authorized environment and confirm scope, impact, and duplicate status.\n\n## Remediation\nApply protocol-specific controls after confirming the root cause.\n\n## Submission Gate\nNever auto-submit; human approval is required."
 prompt=f"Create a professional Web3 security report for {finding.vulnerability_type}. Severity {finding.severity}; location {finding.location}; description {finding.description}; evidence {finding.proof_of_concept}; impact {finding.economic_impact}. Include executive summary, technical explanation, reproduction/PoC, impact, verification steps, remediation, and learning points. Clearly label UNVERIFIED — HUMAN REVIEW REQUIRED and never suggest automatic submission."
 msg=client.messages.create(model=os.environ.get('ANTHROPIC_MODEL','claude-opus-4-1'),max_tokens=3000,messages=[{'role':'user','content':prompt}]); return msg.content[0].text
