"""Backend-authoritative authorization policy for protected research operations."""
from typing import Any, Dict, Iterable

class AuthorizationPolicy:
    """Fail-closed policy based only on backend-stored authorization records.

    Public scope evidence and client acknowledgements are never sufficient. A target is
    authorized only when the persisted opportunity metadata contains an explicit
    authorization record established outside the Android client.
    """
    @staticmethod
    def _record(opportunity: Dict[str, Any]) -> Dict[str, Any]:
        meta = opportunity.get("metadata") or {}
        record = meta.get("authorization_record")
        return record if isinstance(record, dict) else {}

    @classmethod
    def verified(cls, opportunity: Dict[str, Any]) -> bool:
        meta = opportunity.get("metadata") or {}
        record = cls._record(opportunity)
        return (
            meta.get("authorization_confirmed") is True
            and bool(str(record.get("verified_by", "")).strip())
            and bool(str(record.get("basis", "")).strip())
        )

    @classmethod
    def status(cls, opportunity: Dict[str, Any], targets: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        verified = cls.verified(opportunity)
        authorized = []
        if verified:
            for target in targets:
                if target.get("explicitly_published") is True:
                    authorized.append(target.get("identifier"))
        return {
            "verified": verified,
            "authorized_targets": [x for x in authorized if x],
            "reason": "Backend authorization record is required; public scope evidence is not authorization." if not verified else "Backend authorization record verified.",
        }
