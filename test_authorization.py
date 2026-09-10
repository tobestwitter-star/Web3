import os
from authorization import AuthorizationPolicy


def test_scope_evidence_does_not_authorize(monkeypatch):
    monkeypatch.delenv("BUGHUNTER_AUTHORIZATION_RECORDS", raising=False)
    assert not AuthorizationPolicy.verified({"id": "op-1", "metadata": {"scope_evidence": "public"}})


def test_client_style_confirmation_does_not_authorize(monkeypatch):
    monkeypatch.setenv("BUGHUNTER_AUTHORIZATION_RECORDS", "{}")
    assert not AuthorizationPolicy.verified({"id": "op-1", "metadata": {"authorization_confirmed": True}})


def test_unverified_record_does_not_authorize(monkeypatch):
    monkeypatch.setenv("BUGHUNTER_AUTHORIZATION_RECORDS", '{"op-1":{"verified":false,"verified_by":"reviewer","basis":"scope"}}')
    assert not AuthorizationPolicy.verified({"id": "op-1"})


def test_backend_verified_record_authorizes(monkeypatch):
    monkeypatch.setenv("BUGHUNTER_AUTHORIZATION_RECORDS", '{"op-1":{"verified":true,"verified_by":"authorized-reviewer","basis":"program authorization record"}}')
    assert AuthorizationPolicy.verified({"id": "op-1"})


def test_status_exposes_authorized_targets_only_when_backend_verified(monkeypatch):
    target = {"identifier": "repo", "explicitly_published": True}
    monkeypatch.delenv("BUGHUNTER_AUTHORIZATION_RECORDS", raising=False)
    blocked = AuthorizationPolicy.status({"id": "op-1"}, [target])
    assert blocked["verified"] is False
    assert blocked["authorized_targets"] == []
    monkeypatch.setenv("BUGHUNTER_AUTHORIZATION_RECORDS", '{"op-1":{"verified":true,"verified_by":"reviewer","basis":"explicit authorization"}}')
    allowed = AuthorizationPolicy.status({"id": "op-1"}, [target])
    assert allowed["verified"] is True
    assert allowed["authorized_targets"] == ["repo"]


def test_client_cannot_change_backend_record_with_metadata(monkeypatch):
    monkeypatch.setenv("BUGHUNTER_AUTHORIZATION_RECORDS", '{"op-1":{"verified":false,"verified_by":"","basis":""}}')
    opportunity = {"id":"op-1","metadata":{"authorization_record":{"verified":True,"verified_by":"client","basis":"checkbox"}}}
    assert not AuthorizationPolicy.verified(opportunity)
