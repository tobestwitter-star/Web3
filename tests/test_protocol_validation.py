from protocol_validation import build_validation_plan, correlate_execution_evidence, validate_plan
from exploit_harness import HarnessGenerator


def _finding(category='asset_flow'):
    return {
        'id': 'finding-1',
        'title': 'Unauthorized asset flow',
        'category': category,
        'contract': 'Vault',
        'function': 'withdraw',
        'file': 'src/Vault.sol',
        'line': 20,
        'hypothesis': 'attacker-controlled withdrawal can violate the asset authorization invariant',
        'economic_analysis': {'status': 'unquantified'},
    }


def _map():
    return {'functions': [{
        'contract': 'Vault', 'name': 'withdraw', 'file': 'src/Vault.sol', 'line': 20,
        'value_flow': True, 'state_write': True, 'external_call': False,
        'oracle_dependency': False, 'privileged': False,
    }]}


def _path():
    return {'entry_point': 'Vault.withdraw', 'risk_signals': ['asset movement', 'state transition'],
            'preconditions': ['attacker has a reachable user entry point'],
            'sequence': [
                {'step': 1, 'actor': 'attacker', 'action': 'establish initial balance and authorization state'},
                {'step': 2, 'actor': 'attacker', 'action': 'call Vault.withdraw'},
                {'step': 3, 'actor': 'observer', 'action': 'evaluate the asset authorization invariant'},
            ]}


def test_protocol_plan_expresses_ordered_attack_and_invariant():
    plan = build_validation_plan(_finding(), _map(), [_path()])
    assert validate_plan(plan) == []
    assert len(plan['attack_sequence']) == 3
    assert plan['attacker_preconditions']
    assert plan['protocol_state']['before']
    assert plan['security_invariant']
    assert plan['expected_violation']
    assert plan['affected_state']
    assert plan['reachability_constraints']['source_mapped'] is True


def test_unreachable_hypothesis_is_represented_and_not_claimed_reachable():
    finding = _finding()
    plan = build_validation_plan(finding, {'functions': []}, [])
    assert validate_plan(plan) == []
    assert plan['reachability_constraints']['source_mapped'] is False
    assert plan['reachability_constraints']['path_mapped'] is False


def test_malformed_plan_is_rejected():
    bad = build_validation_plan(_finding(), _map(), [_path()])
    bad['security_invariant'] = ''
    bad['attack_sequence'] = []
    assert 'security_invariant' in validate_plan(bad)
    assert 'attack_sequence' in validate_plan(bad)


def test_repeated_identical_engine_evidence_does_not_increase_confidence():
    obs = {'engine': 'forge', 'finding_id': 'finding-1', 'returncode': 0,
           'stdout_sha256': 'same', 'stderr_sha256': 'same',
           'security_assertion': True, 'invariant_result': 'violated',
           'outcome': 'reproduced'}
    one = correlate_execution_evidence([obs])
    repeated = correlate_execution_evidence([obs, dict(obs)])
    assert repeated['repeatable'] is True
    assert repeated['confidence_delta'] == one['confidence_delta']


def test_independent_relevant_engines_can_increase_confidence_and_conflict_reduces_it():
    base = {'finding_id': 'finding-1', 'returncode': 1, 'stdout_sha256': 'a', 'stderr_sha256': 'b',
            'security_assertion': True, 'invariant_result': 'violated', 'outcome': 'reproduced'}
    two = correlate_execution_evidence([{**base, 'engine': 'forge'}, {**base, 'engine': 'halmos', 'stdout_sha256': 'c'}])
    conflict = correlate_execution_evidence([{**base, 'engine': 'forge'}, {**base, 'engine': 'halmos', 'outcome': 'not_reproduced'}])
    assert two['independent_engine_count'] == 2
    assert two['confidence_delta'] > 0
    assert conflict['conflicting'] is True
    assert conflict['confidence_delta'] < two['confidence_delta']


def test_economic_consequence_is_carried_without_inventing_amount():
    finding = _finding('accounting')
    finding['economic_analysis'] = {'impact_score': 0.8, 'status': 'unquantified'}
    plan = build_validation_plan(finding, _map(), [_path()])
    assert plan['economic_consequence']['status'] == 'unquantified'
    assert 'quantify only' in plan['economic_consequence']['requirement']


def test_generated_harness_requires_protocol_plan_and_authorization(tmp_path):
    src = tmp_path / 'src'; src.mkdir()
    (src / 'Vault.sol').write_text('pragma solidity ^0.8.20; contract Vault { uint public balance; function withdraw() external { balance = 0; } }')
    finding = _finding(); finding['file'] = 'Vault.sol'; finding['line'] = 1
    finding['authorized'] = False
    result = HarnessGenerator(str(tmp_path)).generate_foundry(finding)
    assert result['status'] == 'generated'
    assert result['validation_plan']['security_invariant']
    assert result['hypothesis']['authorized'] is False


def test_live_targets_are_never_allowed_by_validation_plan():
    plan = build_validation_plan(_finding(), _map(), [_path()])
    assert plan['reachability_constraints']['live_target_allowed'] is False
    assert plan['reachability_constraints']['requires_authorized_local_execution'] is True
