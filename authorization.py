"""Backend-authoritative authorization policy for protected research operations."""
from __future__ import annotations
import json, os
from pathlib import Path
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
        if not bool(record.get("verified") is True and str(record.get("verified_by", "")).strip() and str(record.get("basis", "")).strip()):
            return False
        return cls._request_target_is_authorized(opportunity)

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
        """Require an authorized opportunity and an explicitly recorded target.

        A backend authorization record must bind the requested target to a repository,
        contract address, or local source root. Client-provided authorization flags and
        public scope evidence are deliberately ignored.
        """
        if not cls._record_verified(opportunity):
            return False, "Backend authorization record is missing or unverified."
        record = cls.record(str(opportunity.get("id", "")))
        source_url = str(target.get("source_url") or target.get("repository") or "").strip()
        address_values = [str(v).strip().lower() for v in (target.get("addresses") or target.get("contracts") or []) if str(v).strip()]
        single_address = str(target.get("address") or target.get("contract_address") or "").strip().lower()
        if single_address:
            address_values.append(single_address)
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
    def _record_verified(cls, opportunity: Dict[str, Any]) -> bool:
        record = cls.record(str(opportunity.get("id", "")))
        return bool(record.get("verified") is True and str(record.get("verified_by", "")).strip() and str(record.get("basis", "")).strip())

    @classmethod
    def _request_target_required(cls) -> bool:
        """Identify Flask API paths that perform target-sensitive operations.

        This hook is intentionally narrow. Public discovery, ranking, scope planning,
        history lookup, and queue administration remain program-level/public operations;
        actual acquisition, engine execution, reproduction-oriented analysis, economic
        analysis, and report generation are target-sensitive and therefore require a
        backend target binding.
        """
        try:
            from flask import has_request_context, request
            if not has_request_context():
                return False
            return request.path in {
                "/api/security-tools/analyze",
                "/api/security-tools/fuzz",
                "/api/research/acquire",
                "/api/research/analyze",
                "/api/research/economic-analysis",
                "/api/research/queue/run-once",
                "/api/analyze-advanced",
                "/api/generate-human-review-report",
            }
        except Exception:
            return False

    @classmethod
    def _request_target(cls) -> Dict[str, Any]:
        try:
            from flask import has_request_context, request
            if not has_request_context():
                return {}
            data = request.get_json(silent=True) or {}
            target = data.get("target") if isinstance(data.get("target"), dict) else {}
            merged = dict(target)
            for key in ("source_url", "repository", "source_dir", "address", "contract_address", "addresses", "contracts"):
                if key in data and key not in merged:
                    merged[key] = data.get(key)
            return merged
        except Exception:
            return {}

    @classmethod
    def _request_target_is_authorized(cls, opportunity: Dict[str, Any]) -> bool:
        if not cls._request_target_required():
            return True
        target = cls._request_target()
        allowed, _ = cls.target_allowed(opportunity, target)
        return allowed

    @classmethod
    def status(cls, opportunity: Dict[str, Any], targets: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        record = cls.record(str(opportunity.get("id", "")))
        record_verified = cls._record_verified(opportunity)
        request_target_required = cls._request_target_required()
        request_target = cls._request_target() if request_target_required else None
        request_target_allowed = True
        request_target_reason = "Not applicable outside target-sensitive API paths."
        if request_target_required and record_verified:
            request_target_allowed, request_target_reason = cls.target_allowed(opportunity, request_target or {})
        verified = record_verified and request_target_allowed
        authorized = [t.get("identifier") for t in targets if record_verified and t.get("explicitly_published") is True and t.get("identifier")]
        return {
            "verified": verified,
            "authorized_targets": authorized,
            "verified_by": record.get("verified_by") if verified else None,
            "basis": record.get("basis") if verified else None,
            "reason": request_target_reason if request_target_required else ("Backend authorization is not established; public scope evidence and client confirmation are insufficient." if not record_verified else "Backend authorization record verified."),
            "target_binding_configured": bool(cls._allowed_values(record, "repositories", "source_urls", "targets", "contract_addresses", "addresses", "source_roots", "workspace_roots")) if record_verified else False,
            "request_target_required": request_target_required,
            "request_target_allowed": request_target_allowed,
        }
