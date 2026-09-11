import json
from pathlib import Path

from main import app
from authorization import AuthorizationPolicy
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


def test_backend_target_binding_requires_explicit_record():
    opportunity = {'id': 'immunefi:fixture'}
    assert AuthorizationPolicy.target_allowed(opportunity, {
        'source_url': 'https://github.com/example/project',
    })[0] is False


def test_backend_target_binding_rejects_unlisted_repository(monkeypatch):
    monkeypatch.setenv('BUGHUNTER_AUTHORIZATION_RECORDS', json.dumps({
        'opportunities': {
            'immunefi:fixture': {
                'verified': True,
                'verified_by': 'authorized-reviewer',
                'basis': 'Explicit authorization record',
                'repositories': ['https://github.com/example/allowed'],
            }
        }
    }))
    opportunity = {'id': 'immunefi:fixture'}
    allowed, _ = AuthorizationPolicy.target_allowed(opportunity, {
        'source_url': 'https://github.com/example/allowed.git',
    })
    denied, reason = AuthorizationPolicy.target_allowed(opportunity, {
        'source_url': 'https://github.com/example/not-allowed',
    })
    assert allowed is True
    assert denied is False
    assert 'not explicitly bound' in reason


def test_backend_target_binding_rejects_program_record_without_target():
    opportunity = {'id': 'immunefi:fixture'}
    # A verified program record without a repository/address/root binding must not
    # silently turn an arbitrary client-supplied source directory into an authorized target.
    import os
    previous = os.environ.pop('BUGHUNTER_AUTHORIZATION_RECORDS', None)
    try:
        os.environ['BUGHUNTER_AUTHORIZATION_RECORDS'] = json.dumps({
            'opportunities': {
                'immunefi:fixture': {
                    'verified': True,
                    'verified_by': 'authorized-reviewer',
                    'basis': 'Explicit authorization record',
                }
            }
        })
        allowed, reason = AuthorizationPolicy.target_allowed(opportunity, {'source_dir': str(Path.cwd())})
        assert allowed is False
        assert 'program-level only' in reason
    finally:
        if previous is None:
            os.environ.pop('BUGHUNTER_AUTHORIZATION_RECORDS', None)
        else:
            os.environ['BUGHUNTER_AUTHORIZATION_RECORDS'] = previous
