"""Read-only Sourcify API v2 integration for source/bytecode provenance."""
from __future__ import annotations
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = "https://sourcify.dev/server/v2"

class SourcifyAdapter:
    name = "sourcify"
    project = "sourcifyeth/sourcify"
    license = "MIT"

    def lookup(self, chain_id: str, address: str, timeout: int = 15) -> dict:
        url = f"{BASE}/contract/{str(chain_id).strip()}/{str(address).strip()}?fields=all"
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "Web3-BugHunter/1.0"})
        try:
            with urlopen(req, timeout=max(1, min(int(timeout), 30))) as response:
                raw = response.read()
                payload = json.loads(raw.decode("utf-8"))
                return {"status": "completed", "http_status": response.status, "url": url, "data": payload}
        except HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:10000]
            return {"status": "not_verified_or_unavailable", "http_status": exc.code, "url": url, "error": body}
        except (URLError, TimeoutError, ValueError) as exc:
            return {"status": "error", "url": url, "error": str(exc)}

    def inventory(self) -> dict:
        return {"name": self.name, "available": True, "binary": None, "kind": "source-verification-lookup", "license": self.license, "project": self.project, "api": "Sourcify API v2", "read_only": True}
