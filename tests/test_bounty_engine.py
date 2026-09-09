import tempfile
from bounty_engine import Opportunity, OpportunityStore, PublicProgramDiscovery, build_report, score_opportunity

def test_scoring_prefers_fast_high_value_targets():
    fast=Opportunity('a','x','Fast','https://x','active',20000,10,True,.1,.2,4,.9,.8,['logic'])
    slow=Opportunity('b','x','Slow','https://y','active',20000,5000,True,.8,.9,80,.9,.8,['logic'])
    assert score_opportunity(fast)>score_opportunity(slow)

def test_store_and_status_history():
    with tempfile.NamedTemporaryFile(suffix='.db') as f:
        s=OpportunityStore(f.name); o=Opportunity('a','x','A','https://example.com','active',5000,1,True,.2,.2,5,.8,.7,['logic']); o.score=score_opportunity(o); s.upsert(o)
        assert s.list(1)[0]['id']=='a'; s.set_hunt_status('a','Verified','human verified',1); assert s.history(1)[0]['status']=='Verified'

def test_report_is_human_gated():
    o=PublicProgramDiscovery().discover_from_json([{'name':'Example','url':'https://example.com','max_bounty_usd':10000}], 'test')[0]
    report=build_report([{'title':'Potential issue'}],o.to_dict()); assert report['do_not_auto_submit'] is True; assert 'UNVERIFIED' in report['review_status']

def test_discovery_includes_reputable_web3_contest_sources():
    sources=PublicProgramDiscovery.SOURCES
    assert {'immunefi_api','hackerone','code4rena','sherlock','codehawks','cantina'} <= set(sources)

def test_immunefi_normalization_preserves_scope_and_reward_metadata():
    programs=PublicProgramDiscovery().discover_from_json([{'project':'Example','slug':'example','maxBounty':250000,'assets':['github.com/example'], 'endDate':'2999-01-01','rules':'safe harbor'}], 'immunefi_api')
    assert programs[0].max_bounty_usd==250000
    assert programs[0].metadata['assets']==['github.com/example']
    assert programs[0].metadata['rules']=='safe harbor'

def test_report_contains_submission_ready_structure_without_claiming_confirmation():
    report=build_report([{'title':'Reentrancy candidate','severity':'high','contract':'Vault','function':'withdraw','description':'External callback before balance update','confidence':0.82,'execution_evidence':{'trace':'local-only'}}],{'name':'Example','source':'immunefi_api','url':'https://example.invalid','scope_notes':'Vault is listed in scope'})
    finding=report['findings'][0]
    assert {'root_cause','attack_scenario','poc_reproduction','evidence','impact','economic_impact','confidence','remediation','scope_evidence','possible_duplicate_indicators','status'} <= set(finding)
    assert finding['status']=='UNVERIFIED — HUMAN REVIEW REQUIRED'
    assert report['do_not_auto_submit'] is True
