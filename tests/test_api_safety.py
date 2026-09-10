import json
from pathlib import Path

from main import app
from bounty_engine import build_report
from candidate_triage import triage_finding
from target_resolution import ScopeResolver


def test_advanced_analysis_requires_explicit_authorization():
    client = app.test_client()
    response = client.post('/api/analyze-advanced', json={'protocol_name': 'fixture', 'code': 'contract C {}'})
    assert response.status_code == 403
    assert 'authorized_scope_verified' in response.get_json()['error']


def test_security_tool_analysis_requires_explicit_authorization():
    client = app.test_client()
    response = client.post('/api/security-tools/analyze', json={'source_dir': str(Path.cwd())})
    assert response.status_code == 403


def test_protected_endpoint_with_unknown_opportunity_is_not_disclosed_as_404():
    client = app.test_client()
    response = client.post('/api/analyze-advanced', json={
        'opportunity_id': 'definitely-not-a-real-opportunity',
        'protocol_name': 'fixture',
        'code': 'contract C {}',
    })
    assert response.status_code == 403
    assert response.get_json()['authorization_required'] is True


def test_security_tool_endpoint_with_unknown_opportunity_is_not_disclosed_as_404():
    client = app.test_client()
    response = client.post('/api/security-tools/analyze', json={
        'opportunity_id': 'definitely-not-a-real-opportunity',
        'source_dir': str(Path.cwd()),
    })
    assert response.status_code == 403


def test_scope_resolution_marks_targets_authorization_required():
    scope = ScopeResolver().resolve(
        {'id': 'x', 'name': 'Fixture', 'source': 'test', 'url': 'https://example.invalid',
         'metadata': {'repositories': ['https://github.com/example/project'],
                      'assets': ['0x' + '1' * 40]}},
        'public program evidence',
    )
    assert scope['authorization_required'] is True
    assert scope['targets']
    assert all(t['authorization_required'] for t in scope['targets'])


def test_report_is_human_review_only():
    report = build_report(
        [{'title': 'Potential issue', 'severity': 'high', 'description': 'Needs reproduction',
          'evidence': ['local evidence'], 'remediation': 'Fix the invariant.'}],
        {'name': 'Fixture', 'source': 'test', 'url': 'https://example.invalid'},
    )
    assert report['review_status'] == 'UNVERIFIED — HUMAN REVIEW REQUIRED'
    assert report['do_not_auto_submit'] is True
    assert 'Submit manually only after human approval.' in report['submission_checklist']


def test_view_function_state_mutation_claim_is_not_bounty_candidate():
    finding = triage_finding({
        'title': 'State update vulnerability',
        'description': 'This function performs a state update.',
        'source_attribution': {'mutability': 'view'},
    })
    assert finding['triage_classification'] == 'false_positive'
    assert finding['bounty_candidate'] is False
