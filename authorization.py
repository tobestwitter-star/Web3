"""Backend-authoritative authorization policy for protected research operations."""
from __future__ import annotations
import json, os
from typing import Any, Dict, Iterable

class AuthorizationPolicy:
    """Fail-closed authorization sourced only from backend configuration.

    Public scope evidence, client acknowledgements, and request-body flags are never
    authorization. A program is authorized only when its opportunity id is present in
    the backend-only BUGHUNTER_AUTHORIZATION_RECORDS configuration.
    """
    ENV = "BUGHUNTER_AUTHORIZATION_RECORDS"

    @classmethod
    def _records(cls) -> Dict[str, Dict[str, Any]]:
        raw = os.environ.get(cls.ENV, "").strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            return {}
        if isinstance(data, dict) and isinstance(data.get("opportunities"), dict):
            data = data["opportunities"]
        if not isinstance(data, dict):
            return {}
        return {str(k): v for k, v in data.items() if isinstance(v, dict)}

    @classmethod
    def record(cls, opportunity_id: str) -> Dict[str, Any]:
        record = cls._records().get(str(opportunity_id), {})
        return record if isinstance(record, dict) else {}

    @classmethod
    def verified(cls, opportunity: Dict[str, Any]) -> bool:
        record = cls.record(str(opportunity.get("id", "")))
        return bool(record.get("verified") is True and str(record.get("verified_by", "")).strip() and str(record.get("basis", "")).strip())

    @classmethod
    def status(cls, opportunity: Dict[str, Any], targets: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        record = cls.record(str(opportunity.get("id", "")))
        verified = cls.verified(opportunity)
        authorized = [t.get("identifier") for t in targets if verified and t.get("explicitly_published") is True and t.get("identifier")]
        return {
            "verified": verified,
            "authorized_targets": authorized,
            "verified_by": record.get("verified_by") if verified else None,
            "basis": record.get("basis") if verified else None,
            "reason": "Backend authorization is not established; public scope evidence and client confirmation are insufficient." if not verified else "Backend authorization record verified.",
        }
