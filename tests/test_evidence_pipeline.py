from professional_report import build_professional_report, STATUS
from research_pipeline import FindingCorrelator, ResearchPipeline


def test_structured_engine_observations_survive_correlation():
    raw={'id':'sl-1','title':'Reentrancy','severity':'high','confidence':0.9,'location':'src/Vault.sol:40','evidence':[{'source_mapping':{'filename_relative':'src/Vault.sol','lines':[40,41]}}]}
    result=FindingCorrelator().correlate([{'engine':'slither','findings':[raw]}])
    assert result[0]['engine_observations'][0]['engine']=='slither'
    assert result[0]['engine_observations'][0]['raw_evidence']==raw['evidence']


def test_report_prefers_authoritative_registry_over_flattened_fields():
    finding={'id':'f-1','title':'Candidate','severity':'high','engine_observations':[{'engine':'fake','evidence':['flattened']}],'execution_evidence':{'status':'executed','trace':'flattened'}}
    registry={'f-1':{'engine_observations':[{'engine':'forge','structured_result':{'status':'completed','command':['forge','test']}}],'execution_metadata':[{'status':'completed','command':['forge','test'],'duration_seconds':1.2}],'provenance':[{'engine':'forge','version':'forge 1.0','stdout_sha256':'abc'}],'reproduction':{'status':'assertion_failed','trace':{'pc':[1,2]},'inputs':{'amount':7}},'symbolic':{'tool':'halmos','evidence_level':'symbolic_counterexample'},'invariant':{'tool':'forge-invariant','evidence_level':'no_invariant_failure_observed'},'conflicts':[{'engines':['slither','forge'],'reason':'one reports risk, one has no failing regression'}]}}
    report=build_professional_report([finding],{'name':'Demo'},{'scope':{},'evidence_registry':registry,'authorization_confirmed':True})
    f=report['findings'][0]
    assert f['engine_evidence'][0]['engine']=='forge'
    assert f['reproduction']['inputs']=={'amount':7}
    assert f['execution_metadata'][0]['duration_seconds']==1.2
    assert f['evidence_provenance'][0]['engine']=='forge'
    assert f['conflicting_evidence'][0]['reason'].startswith('one reports')
    assert f['traces_inputs_coverage_symbolic']['symbolic']['tool']=='halmos'


def test_malformed_and_partial_registry_stays_explicit():
    finding={'id':'f-2','title':'Partial'}
    report=build_professional_report([finding],{}, {'evidence_registry':{'f-2':{'reproduction':'not-a-record','conflicts':'bad'}}})
    f=report['findings'][0]
    assert f['reproduction']['malformed']=='not-a-record'
    assert f['conflicting_evidence']==[]
    assert f['engine_evidence']==[]
    assert f['review_status']==STATUS


def test_pipeline_registry_contains_stage1_and_candidate_provenance_without_fabrication():
    p=ResearchPipeline()
    orchestration={'stage1':{'results':[{'tool':'slither','version':'0.1','result':{'status':'completed'},'evidence_provenance':{'engine':'slither','command':['slither','.'],'stdout_sha256':'s'},'findings':[{'id':'f-3','title':'Candidate','evidence':[{'element':'x'}]}]}]}}
    candidate={'candidates':[{'finding_id':'f-3','execution':[{'tool':'forge','status':'executed','command':['forge','test'],'evidence':{'status':'assertion_failed'}}]}]}
    ranked=[{'id':'f-3','title':'Candidate','engine_observations':[], 'economic_analysis':None,'attack_paths':[]}]
    reg=p._evidence_registry(ranked,candidate,{'tool':'halmos','status':'skipped'}, {'tool':'forge-invariant','status':'executed'}, orchestration, [])
    assert reg['f-3']['engine_observations'][0]['engine']=='slither'
    assert any(x['engine']=='forge' for x in reg['f-3']['provenance'])
    assert reg['f-3']['reproduction']['status']=='assertion_failed'
