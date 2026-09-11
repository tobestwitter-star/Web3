"""Backend-authoritative authorization policy for protected research operations."""
from __future__ import annotations
import json, os
from pathlib import Path
from typing import Any, Dict, Iterable
from urllib.parse import urlparse

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
    def _allowed_values(cls, record: Dict[str, Any], *keys: str) -> list[str]:
        values: list[str] = []
        for key in keys:
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                values.append(value.strip())
            elif isinstance(value, (list, tuple, set)):
                values.extend(str(v).strip() for v in value if str(v).strip())
        return values

    @classmethod
    def target_allowed(cls, opportunity: Dict[str, Any], target: Dict[str, Any]) -> tuple[bool, str]:
        """Require an authorized opportunity *and* an explicitly recorded target.

        The backend record may optionally bind authorization to repository URLs,
        contract addresses, or local workspace roots. If a binding is supplied, a
        target must match it. If no binding is supplied, protected API authorization
        remains valid for program-level operations, but target-sensitive operations
        should fail closed rather than treating a client-provided target as authorized.
        """
        if not cls.verified(opportunity):
            return False, "Backend authorization record is missing or unverified."
        record = cls.record(str(opportunity.get("id", "")))
        source_url = str(target.get("source_url") or target.get("repository") or "").strip()
        address_values = [str(v).strip().lower() for v in (target.get("addresses") or target.get("contracts") or []) if str(v).strip()]
        allowed_urls = cls._allowed_values(record, "repositories", "source_urls", "targets")
        allowed_addresses = [v.lower() for v in cls._allowed_values(record, "contract_addresses", "addresses")]
        allowed_roots = [str(v).strip() for v in cls._allowed_values(record, "source_roots", "workspace_roots")]
        if not (allowed_urls or allowed_addresses or allowed_roots):
            return False, "Backend authorization is program-level only; no explicit authorized target binding is configured."
        if source_url and allowed_urls:
            normalized = source_url.rstrip("/").removesuffix(".git").lower()
            for allowed in allowed_urls:
                candidate = allowed.rstrip("/").removesuffix(".git").lower()
                if normalized == candidate:
                    return True, "Explicit backend repository authorization matched."
        if address_values and allowed_addresses and any(a in allowed_addresses for a in address_values):
            return True, "Explicit backend contract authorization matched."
        source_dir = str(target.get("source_dir") or "").strip()
        if source_dir and allowed_roots:
            try:
                resolved = Path(source_dir).resolve()
                for root in allowed_roots:
                    authorized_root = Path(root).resolve()
                    if resolved == authorized_root or authorized_root in resolved.parents:
                        return True, "Explicit backend local source-root authorization matched."
            except OSError:
                pass
        return False, "Target is not explicitly bound to the backend authorization record."

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
            "target_binding_configured": bool(cls._allowed_values(record, "repositories", "source_urls", "targets", "contract_addresses", "addresses", "source_roots", "workspace_roots")) if verified else False,
        }
