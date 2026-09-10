import tempfile
from pathlib import Path
from research_pipeline import Target, TargetAcquirer, FindingCorrelator, ResearchPipeline

def test_extract_public_github_target_and_address():
    acq=TargetAcquirer()
    opp={'name':'Demo','metadata':{'repository':'https://github.com/example/protocol'}}
    targets=acq.extract_targets(opp,'authorized scope includes https://github.com/example/protocol and 0x1111111111111111111111111111111111111111')
    assert len(targets)==1
    assert targets[0].source_url=='https://github.com/example/protocol'
    assert targets[0].addresses==['0x1111111111111111111111111111111111111111']

def test_extract_address_only_target_when_no_repository_is_published():
    acq=TargetAcquirer()
    targets=acq.extract_targets({'name':'Demo','metadata':{}},'authorized scope includes 0x2222222222222222222222222222222222222222')
    assert len(targets)==1
    assert targets[0].kind=='evm_contract'
    assert targets[0].addresses==['0x2222222222222222222222222222222222222222']

def test_acquisition_requires_authorization():
    with tempfile.TemporaryDirectory() as td:
        t=Target('demo','https://github.com/example/protocol',authorized=False)
        result=TargetAcquirer().clone_public_repo(t,td,False)
        assert result['blocked']=='authorization_required'

def test_correlator_merges_cross_tool_findings():
    c=FindingCorrelator()
    findings=c.correlate([
        {'engine':'existing_analyzer','findings':[{'title':'Reentrancy','description':'external callback before state update','severity':'high','location':'Vault.sol:40','confidence':.8}]},
        {'engine':'slither','findings':[{'title':'Reentrancy','description':'external callback before state update','severity':'high','location':'Vault.sol:40','confidence':.6}]}
    ])
    assert len(findings)==1
    assert findings[0]['validated_by_multiple_tools'] is True
    assert findings[0]['status']=='UNVERIFIED — HUMAN REVIEW REQUIRED'

def test_pipeline_blocks_without_authorization():
    result=ResearchPipeline().analyze_local('/tmp/does-not-matter','demo',source_code='contract Demo {}',authorization_confirmed=False)
    assert result['status']=='blocked'
