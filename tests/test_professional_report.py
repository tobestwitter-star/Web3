from professional_report import build_professional_report, STATUS, DUPLICATE


def base_finding():
    return {
        'id':'f-1','title':'Reentrancy in Vault.withdraw','severity':'high',
        'description':'External callback occurs before state update.',
        'contract':'Vault','function':'withdraw','location':'src/Vault.sol:40',
        'root_cause':'State is updated after the external call.',
        'attack_paths':[{'entry_point':'Vault.withdraw','steps':['deposit','withdraw','callback']}],
        'engines':['slither','forge','ityfuzz'],
        'validated_by_multiple_tools':True,'cross_tool_confidence':0.91,
        'engine_observations':[{'engine':'slither','evidence':['reentrancy check']},{'engine':'forge','evidence':['failing regression test']}],
        'execution_evidence':{'status':'executed','trace':'local trace','inputs':{'amount':1}},
        'reproducibility':0.88,'economic_analysis':{'estimated_loss_usd':125000},
        'historical_intelligence':{'matches':[
            {'match_type':'exact_normalized_fingerprint','reference':{'source':'DeFiHackLabs','reference':'case-1'}},
            {'match_type':'semantic_similarity_lead','similarity':0.84,'reference':{'source':'GitHub','reference':'case-2'}}]},
        'possible_duplicate_indicators':[{'match_type':'exact_normalized_fingerprint','reference':{'source':'DeFiHackLabs','reference':'case-1'}}],
        'duplicate_classification':DUPLICATE,'evidence_provenance':['sha256:abc'],
        'remediation':'Update state before the external interaction.','scope_evidence':'Vault is explicitly listed.',
    }


def test_complete_finding_generates_professional_report():
    r=build_professional_report([base_finding()], {'id':'op-1','name':'Demo','source':'immunefi_api'}, {'authorization_confirmed':True,'scope':{'repositories':['https://github.com/example/demo']}})
    f=r['findings'][0]
    assert r['review_status']==STATUS and r['do_not_auto_submit'] is True
    assert f['source_locations']==['src/Vault.sol:40']
    assert f['engine_provenance']==['slither','forge','ityfuzz']
    assert len(f['exact_historical_fingerprint_matches'])==1
    assert len(f['semantic_similarity_leads'])==1
    assert f['duplicate_status']==DUPLICATE


def test_partial_evidence_is_not_fabricated():
    r=build_professional_report([{'title':'Candidate','severity':'medium'}], {'name':'Demo'}, {})
    f=r['findings'][0]
    assert f['source_locations']==[]
    assert f['economic_impact'] is None
    assert f['reproduction']['evidence'] is None
    assert f['engine_evidence']==[]
    assert f['review_status']==STATUS


def test_conflicting_engine_results_remain_observational():
    f=base_finding(); f['engine_observations']=[
        {'engine':'slither','evidence':['high']},
        {'engine':'forge','evidence':['no failing test']},
    ]; f['limitations']=['Conflicting engine observations require human adjudication.']
    r=build_professional_report([f], {'name':'Demo'}, {'authorization_confirmed':True})
    assert len(r['findings'][0]['engine_evidence'])==2
    assert r['findings'][0]['review_status']==STATUS
    assert r['findings'][0]['limitations']==['Conflicting engine observations require human adjudication.']


def test_unverified_and_duplicate_rules_are_enforced():
    r=build_professional_report([base_finding()], {'name':'Demo'}, {'authorization_confirmed':True})
    assert r['human_review_only'] is True
    assert r['submission']['automatic_submission'] is False
    assert r['submission']['manual_submission_allowed_only_after_human_approval'] is True
    assert all(f['review_status']==STATUS for f in r['findings'])
    assert r['findings'][0]['duplicate_status']==DUPLICATE
