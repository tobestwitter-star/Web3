from historical_intelligence import HistoricalIntelligence


def test_historical_sources_include_defihacklabs_and_require_review():
    leads = HistoricalIntelligence().search_urls("oracle manipulation", "oracle")
    sources = {item["source"] for item in leads}
    assert "defi_hacklabs" in sources
    assert all(item["requires_human_review"] for item in leads)


def test_historical_exact_fingerprint_is_not_an_automatic_duplicate():
    engine = HistoricalIntelligence()
    finding = {
        "title": "Oracle price manipulation",
        "category": "oracle",
        "description": "Attacker can manipulate the oracle price before settlement.",
        "root_cause": "Spot price is trusted without a manipulation-resistant source.",
        "location": "Vault.sol:88",
    }
    matches = engine.compare(finding, [dict(finding, reference="old")])
    assert matches[0]["match_type"] == "exact_normalized_fingerprint"
    assert matches[0]["duplicate_decision"] == "POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED"
