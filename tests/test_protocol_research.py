import tempfile
from pathlib import Path
from protocol_research import ProtocolMapper,BusinessLogicEngine,FindingPrioritizer
from target_resolution import BuildDetector

def test_protocol_mapper_and_business_logic():
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/'Vault.sol';p.write_text('''pragma solidity ^0.8.20; contract Vault { address public owner; uint public totalAssets; function withdraw(uint amount) external { (bool ok,)=msg.sender.call{value:amount}(""); totalAssets -= amount; } }''')
        mapped=ProtocolMapper().map(td)
        assert mapped['architecture']['contract_count']==1
        assert mapped['architecture']['external_call_count']>=1
        hs=BusinessLogicEngine().hypotheses(td,mapped)
        assert hs and any(x['category']=='external_call' for x in hs)

def test_build_detector_and_prioritizer():
    with tempfile.TemporaryDirectory() as td:
        Path(td,'foundry.toml').write_text('[profile.default]\nsrc="src"\n')
        Path(td,'A.sol').write_text('contract A {}')
        assert BuildDetector().detect(td)['primary']=='foundry'
    ranked=FindingPrioritizer().rank([{'title':'high','severity':'high','exploitability':.9,'economic_impact_score':.9,'confidence':.8,'reproducibility':.7,'independent_signals':2},{'title':'low','severity':'low','exploitability':.3,'economic_impact_score':.2,'confidence':.3,'reproducibility':.1,'independent_signals':1}],{'max_bounty_usd':10000})
    assert ranked[0]['title']=='high'
    assert all(x['status']=='UNVERIFIED — HUMAN REVIEW REQUIRED' for x in ranked)

def test_historical_similarity():
    from historical_intelligence import HistoricalIntelligence
    h=HistoricalIntelligence();assert h.similarity('oracle price manipulation lending','oracle price manipulation lending protocol')>.5
