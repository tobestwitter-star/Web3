package com.web3bughunter.android

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ProfessionalReportTest {
    private fun finding(): JSONObject = JSONObject().apply {
        put("finding_id", "f-1")
        put("severity", "high")
        put("confidence", 0.91)
        put("engine_evidence", JSONArray().apply { put(JSONObject().put("engine", "slither")); put(JSONObject().put("engine", "forge")) })
        put("engine_provenance", JSONArray().apply { put(JSONObject().put("engine", "forge").put("version", "1.0").put("command", "forge test")) })
        put("execution_metadata", JSONArray().apply { put(JSONObject().put("status", "executed").put("returncode", 0)) })
        put("reproduction", JSONObject().put("status", "demonstrated").put("trace", "call trace"))
        put("traces_inputs_coverage_symbolic", JSONObject().put("coverage", JSONObject().put("lines", 42)).put("symbolic", JSONObject().put("status", "executed")).put("invariants", JSONObject().put("status", "executed")))
        put("evidence_provenance", JSONArray().apply { put(JSONObject().put("engine", "forge").put("sha256", "abc")) })
        put("historical_context", JSONArray().apply { put(JSONObject().put("match_type", "semantic_similarity_lead")) })
        put("economic_impact", JSONObject().put("estimated_loss_usd", 125000))
        put("remediation", "Update state before external interaction.")
        put("limitations", JSONArray().apply { put("Requires human reproduction") })
    }

    @Test fun completeStructuredReportPreservesAuthoritativeFields() {
        val f = finding().put("review_status", REPORT_REVIEW_STATUS).put("duplicate_status", REPORT_DUPLICATE_STATUS)
        val parsed = ProfessionalReport(JSONObject().put("review_status", REPORT_REVIEW_STATUS).put("do_not_auto_submit", true).put("human_review_only", true).put("findings", JSONArray().put(f)))
        assertEquals(REPORT_REVIEW_STATUS, parsed.reviewStatus)
        assertTrue(parsed.doNotAutoSubmit)
        assertTrue(parsed.humanReviewOnly)
        assertEquals(1, parsed.findings.length())
        assertEquals("high", parsed.finding(0)!!.getString("severity"))
        assertEquals(REPORT_DUPLICATE_STATUS, parsed.duplicateStatus(parsed.finding(0)!!))
        assertEquals(2, parsed.finding(0)!!.getJSONArray("engine_evidence").length())
        assertEquals("forge", parsed.finding(0)!!.getJSONArray("engine_provenance").getJSONObject(0).getString("engine"))
        assertTrue(parsed.hasDemonstratedEvidence(parsed.finding(0)!!))
        assertEquals("abc", parsed.finding(0)!!.getJSONArray("evidence_provenance").getJSONObject(0).getString("sha256"))
        assertEquals("semantic_similarity_lead", parsed.finding(0)!!.getJSONArray("historical_context").getJSONObject(0).getString("match_type"))
        assertEquals(125000, parsed.finding(0)!!.getJSONObject("economic_impact").getInt("estimated_loss_usd"))
    }

    @Test fun reproductionSymbolicInvariantAndProvenanceRemainStructured() {
        val parsed = ProfessionalReport(JSONObject().put("findings", JSONArray().put(finding())))
        val f = parsed.finding(0)!!
        assertEquals("demonstrated", f.getJSONObject("reproduction").getString("status"))
        assertEquals("call trace", f.getJSONObject("reproduction").getString("trace"))
        assertEquals(42, f.getJSONObject("traces_inputs_coverage_symbolic").getJSONObject("coverage").getInt("lines"))
        assertEquals("executed", f.getJSONObject("traces_inputs_coverage_symbolic").getJSONObject("symbolic").getString("status"))
        assertEquals("executed", f.getJSONObject("traces_inputs_coverage_symbolic").getJSONObject("invariants").getString("status"))
        assertEquals("forge", f.getJSONArray("evidence_provenance").getJSONObject(0).getString("engine"))
    }

    @Test fun unknownFieldsAndPartialReportsRemainForwardCompatible() {
        val f = JSONObject().put("finding_id", "f-2").put("unknown_engine_field", "preserve raw JSON")
        val parsed = ProfessionalReport(JSONObject().put("review_status", REPORT_REVIEW_STATUS).put("future_field", JSONObject().put("value", true)).put("findings", JSONArray().put(f)))
        assertEquals(REPORT_REVIEW_STATUS, parsed.reviewStatus)
        assertEquals("preserve raw JSON", parsed.finding(0)!!.getString("unknown_engine_field"))
        assertFalse(parsed.hasDemonstratedEvidence(parsed.finding(0)!!))
    }

    @Test fun missingEvidenceIsDistinctFromDemonstratedEvidence() {
        val f = JSONObject().put("finding_id", "f-3").put("reproduction", JSONObject().put("status", "not demonstrated"))
        val parsed = ProfessionalReport(JSONObject().put("findings", JSONArray().put(f)))
        assertFalse(parsed.hasDemonstratedEvidence(parsed.finding(0)!!))
        assertEquals("not demonstrated", parsed.finding(0)!!.getJSONObject("reproduction").getString("status"))
    }

    @Test fun malformedEvidenceDoesNotBecomeAnExecutionClaim() {
        val f = JSONObject().put("finding_id", "f-4").put("reproduction", "malformed")
        val parsed = ProfessionalReport(JSONObject().put("findings", JSONArray().put(f)))
        assertFalse(parsed.hasDemonstratedEvidence(parsed.finding(0)!!))
        assertEquals("malformed", parsed.finding(0)!!.getString("reproduction"))
    }

    @Test fun reviewPolicyConstantsAreImmutableContractValues() {
        assertEquals("UNVERIFIED — HUMAN REVIEW REQUIRED", REPORT_REVIEW_STATUS)
        assertEquals("POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED", REPORT_DUPLICATE_STATUS)
    }
}
