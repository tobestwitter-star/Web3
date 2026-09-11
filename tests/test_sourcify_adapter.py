import json
from urllib.error import HTTPError
from sourcify_adapter import SourcifyAdapter


def test_sourcify_inventory_is_read_only():
    meta = SourcifyAdapter().inventory()
    assert meta["available"] is True
    assert meta["read_only"] is True
    assert meta["api"] == "Sourcify API v2"


def test_sourcify_lookup_normalizes_http_error(monkeypatch):
    def fail(*args, **kwargs):
        raise HTTPError("https://sourcify.dev/server/v2/contract/1/0x0", 404, "not found", {}, None)

    monkeypatch.setattr("sourcify_adapter.urlopen", fail)
    result = SourcifyAdapter().lookup("1", "0x0000000000000000000000000000000000000001")
    assert result["status"] == "not_verified_or_unavailable"
    assert result["http_status"] == 404
