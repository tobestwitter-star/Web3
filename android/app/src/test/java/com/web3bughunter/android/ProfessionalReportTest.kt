package com.web3bughunter.android

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ProfessionalReportTest {
    private fun completeReport(): JSONObject = JSONObject().apply {
        put("report_version", "1.1")
        put("review_status", REPORT_REVIEW_STATUS)
        put("do_not_auto_submit", true)
        put("human_review_only", true)
        put("scope_and_authorization", JSONObject().put("scope", "authorized scope").put("authorization", JSONObject().put("confirmed", true)))
        put("limitations", JSONArray().put("Missing evidence is not inferred or fabricated."))
        put("findings", JSONArray().put(JSONObject().apply {
            put("finding_id", "f-1")
            put("title", "Reentrancy")
            put("severity", "high")
            put("confidence", 0.91)
            put("review_status", REPORT_REVIEW_STATUS)
            put("duplicate_status", REPORT_DUPLICATE_STATUS)
            put("engine_evidence", JSONArray().put(JSONObject().put("engine", "slither").put("raw_evidence", JSONArray().put("structured slither evidence"))).put(JSONObject().put("engine", "forge").put("raw_evidence", JSONArray().put("structured forge evidence")))
            put("engine_provenance", JSONArray().put(JSONObject().put("engine", "forge").put("version", "1.0").put("command", "forge test")))
            put("execution_metadata", JSONArray().put(JSONObject().put("status", "executed").put("returncode", 0).put("command", "forge test")))
            put("reproduction", JSONObject().put("status", "demonstrated").put("evidence", JSONObject().put("trace", "call trace").put("inputs", JSONObject().put("amount", 1))))
            put("traces_inputs_coverage_symbolic", JSONObject().put("trace", "call trace").put("inputs", JSONObject().put("amount", 1)).put("coverage", JSONObject().put("lines", 42)).put("symbolic", JSONObject().put("status", "executed")).put("invariants", JSONObject().put("status", "executed")))
            put("evidence_provenance", JSONArray().put(JSONObject().put("engine", "forge").put("sha256", "abc")))
            put("historical_context", JSONArray().put(JSONObject().put("match_type", "semantic_similarity_lead").put("similarity", 0.84)))
            put("economic_impact", JSONObject().put("estimated_loss_usd", 125000))
            put("remediation", "Update state before external interaction.")
            put("limitations", JSONArray().put("Requires independent human reproduction."))
        }))
    }

    @Test fun completeStructuredReportPreservesAuthoritativeFields() {
        val report = completeReport().toProfessionalReport()
        assertEquals(REPORT_REVIEW_STATUS, report.reviewStatus)
        assertTrue(report.doNotAutoSubmit)
        assertTrue(report.humanReviewOnly)
        assertEquals(1, report.findings.length())
        val finding = report.finding(0)!!
        assertEquals("high", finding.getString("severity"))
        assertEquals(REPORT_DUPLICATE_STATUS, report.duplicateStatus(finding))
        assertEquals(2, finding.getJSONArray("engine_evidence").length())
        assertEquals(1, finding.getJSONArray("engine_provenance").length())
        assertTrue(report.hasDemonstratedEvidence(finding))
    }

    @Test fun unknownFieldsAndPartialReportsRemainForwardCompatible() {
        val report = JSONObject().put("review_status", REPORT_REVIEW_STATUS).put("future_field", JSONObject().put("value", true)).put("findings", JSONArray().put(JSONObject().put("finding_id", "f-2").put("severity", "medium").put("unknown_engine_field", "preserve raw JSON")))
        val parsed = report.toProfessionalReport()
        assertEquals(REPORT_REVIEW_STATUS, parsed.reviewStatus)
        assertEquals("preserve raw JSON", parsed.finding(0)!!.getString("unknown_engine_field"))
        assertFalse(parsed.hasDemonstratedEvidence(parsed.finding(0)!!))
    }

    @Test fun missingEvidenceIsDistinctFromDemonstratedEvidence() {
        val finding = JSONObject().put("finding_id", "f-3").put("reproduction", JSONObject().put("status", "not demonstrated").put("evidence", JSONObject.NULL))
        val report = JSONObject().put("findings", JSONArray().put(finding)).toProfessionalReport()
        assertFalse(report.hasDemonstratedEvidence(report.finding(0)!!))
        assertEquals("not demonstrated", report.finding(0)!!.getJSONObject("reproduction").getString("status"))
    }

    @Test fun malformedEvidenceDoesNotBecomeAnExecutionClaim() {
        val finding = JSONObject().put("finding_id", "f-4").put("reproduction", "malformed")
        val report = JSONObject().put("findings", JSONArray().put(finding)).toProfessionalReport()
        assertFalse(report.hasDemonstratedEvidence(report.finding(0)!!))
        assertEquals("malformed", report.finding(0)!!.getString("reproduction"))
    }
}
