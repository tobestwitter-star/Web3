"""Conservative quantitative impact estimation from source-derived evidence only."""
from __future__ import annotations
import re
from typing import Any,Dict

class EconomicAnalyzer:
 def analyze(self,finding:Dict[str,Any],context:str='')->Dict[str,Any]:
  text=' '.join([str(finding.get(k,'')) for k in ('title','description','hypothesis','evidence')])+' '+context
  low=text.lower(); assumptions=[]; formulas=[]; ranges={}
  if any(x in low for x in ('round','precision','decimal','muldiv','share')):
   formulas.append('Potential unit/rounding delta = intended_amount - implemented_amount')
   assumptions.append('Token decimals and rounding direction must be confirmed from source/tests; no market price assumed.')
  if any(x in low for x in ('oracle','price','twap','latestanswer','chainlink')):
   formulas.append('Potential price-sensitive loss = affected_notional × |observed_price - reference_price| / reference_price')
   assumptions.append('Reference price, manipulation window, liquidity and affected notional must be measured; no price is invented.')
  if any(x in low for x in ('fee','interest','debt','borrow','collateral')):
   formulas.append('Potential economic delta = affected_balance × rate_delta × applicable_period')
   assumptions.append('Balance, rate and time period must come from reproducible local state or explicit test inputs.')
  if any(x in low for x in ('transfer','withdraw','mint','burn','asset','token','liquidity')):
   formulas.append('Potential unauthorized extraction = attacker_received_assets - attacker_required_assets')
   assumptions.append('Asset quantities must be established by the reproduction trace; market valuation is optional and externally sourced.')
  flash='flash' in low or 'flashloan' in low or 'flash loan' in low
  if flash:
   formulas.append('Atomic attack gain = proceeds_after_sequence - principal - fees')
   assumptions.append('Flash-loan availability and fee must be verified in the authorized local fork/harness; availability alone is not proof.')
  return {'economic_impact':'quantitative_candidate' if formulas else 'qualitative_only','formulas':formulas,'assumptions':assumptions,'estimated_range':ranges,'status':'UNVERIFIED — HUMAN REVIEW REQUIRED','no_invented_figures':True,'flash_loan_assisted':flash}
