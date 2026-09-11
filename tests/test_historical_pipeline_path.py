from research_pipeline import FindingCorrelator, ResearchPipeline, STATUS, DUPLICATE
from bounty_engine import build_report


def test_lifecycle_keeps_exact_and_semantic_historical_matches_distinct():
    history = ResearchPipeline().history
    finding = {
        'title': 'Oracle price manipulation',
        'category': 'oracle',
        'description': 'Attacker can manipulate the oracle price before settlement.',
        'root_cause': 'Spot price is trusted without a manipulation-resistant source.',
        'location': 'Vault.sol:88',
    }
    exact = dict(finding, reference='exact')
    semantic = {
        'title': 'Oracle settlement manipulation',
        'category': 'oracle',
        'description': 'An attacker can influence the oracle before a settlement operation.',
        'root_cause': 'Settlement relies on a manipulable price source.',
        'location': 'OtherVault.sol:91',
        'reference': 'semantic',
    }
    matches = history.compare(finding, [exact, semantic])
    assert matches[0]['match_type'] == 'exact_normalized_fingerprint'
    assert matches[0]['duplicate_decision'] == DUPLICATE
    assert any(m['match_type'] == 'semantic_similarity_lead' for m in matches[1:])
    assert all(m['duplicate_decision'] == DUPLICATE for m in matches)


def test_historical_lookup_explicitly_invokes_defihacklabs():
    pipeline = ResearchPipeline()
    calls = []
    pipeline.history.search_defi_hacklabs = lambda finding, max_records=5: calls.append((finding, max_records)) or []
    result = pipeline.history.lookup({'title': 'Oracle manipulation', 'category': 'oracle', 'description': 'price'}, ['defi_hacklabs'], 3)
    assert calls and calls[0][1] == 3
    assert result['invocations'][0]['source'] == 'defi_hacklabs'
    assert result['invocations'][0]['invoked'] is True
    assert result['historical_evidence_only'] is True


def test_correlated_finding_is_human_gated_before_report():
    c = FindingCorrelator()
    finding = c.correlate([{'engine': 'slither', 'findings': [{
        'title': 'Oracle price manipulation', 'description': 'Manipulable oracle before settlement',
        'severity': 'high', 'category': 'oracle', 'location': 'Vault.sol:88', 'confidence': .8
    }]}])[0]
    finding['possible_duplicate_indicators'] = [{
        'match_type': 'exact_normalized_fingerprint',
        'similarity': 1.0,
        'duplicate_decision': DUPLICATE,
        'reference': {'source': 'defi_hacklabs', 'reference': 'public-reference'}
    }]
    finding['duplicate_classification'] = DUPLICATE
    report = build_report([finding], {'name': 'Example', 'scope_notes': 'Authorized scope requires human verification.'})
    out = report['findings'][0]
    assert out['possible_duplicate_indicators'][0]['duplicate_decision'] == DUPLICATE
    assert out['status'] == STATUS
    assert report['review_status'] == STATUS
    assert report['do_not_auto_submit'] is True
