package com.web3bughunter.android

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ProfessionalReportTest {
    private fun report(json: String): ProfessionalReport = JSONObject(json.trimIndent()).toProfessionalReport()

    @Test fun completeStructuredReportPreservesAuthoritativeFields() {
        val parsed = report("""
            {"review_status":"unverified","do_not_auto_submit":true,"human_review_only":true,"findings":[{"finding_id":"f-1","severity":"high","confidence":0.91,"engine_evidence":[{"engine":"slither"},{"engine":"forge"}],"engine_provenance":[{"engine":"forge","version":"1.0","command":"forge test"}],"execution_metadata":[{"status":"executed","returncode":0}],"reproduction":{"status":"demonstrated"},"evidence_provenance":[{"engine":"forge","sha256":"abc"}],"historical_context":[{"match_type":"semantic_similarity_lead"}],"economic_impact":{"estimated_loss_usd":125000},"remediation":"Update state before external interaction.","limitations":["Requires human reproduction"]}]}
        """)
        parsed.raw.put("review_status", REPORT_REVIEW_STATUS)
        parsed.finding(0)!!.put("review_status", REPORT_REVIEW_STATUS).put("duplicate_status", REPORT_DUPLICATE_STATUS)
        assertEquals(REPORT_REVIEW_STATUS, parsed.reviewStatus)
        assertTrue(parsed.doNotAutoSubmit)
        assertTrue(parsed.humanReviewOnly)
        val finding = parsed.finding(0)!!
        assertEquals("high", finding.getString("severity"))
        assertEquals(REPORT_DUPLICATE_STATUS, parsed.duplicateStatus(finding))
        assertEquals(2, finding.getJSONArray("engine_evidence").length())
        assertEquals("forge", finding.getJSONArray("engine_provenance").getJSONObject(0).getString("engine"))
        assertTrue(parsed.hasDemonstratedEvidence(finding))
        assertEquals("abc", finding.getJSONArray("evidence_provenance").getJSONObject(0).getString("sha256"))
        assertEquals("semantic_similarity_lead", finding.getJSONArray("historical_context").getJSONObject(0).getString("match_type"))
        assertEquals(125000, finding.getJSONObject("economic_impact").getInt("estimated_loss_usd"))
    }

    @Test fun reproductionSymbolicInvariantAndProvenanceRemainStructured() {
        val parsed = report("""
            {"findings":[{"reproduction":{"status":"demonstrated","trace":"call trace","inputs":{"amount":1}},"traces_inputs_coverage_symbolic":{"trace":"call trace","inputs":{"amount":1},"coverage":{"lines":42},"symbolic":{"status":"executed"},"invariants":{"status":"executed"}},"evidence_provenance":[{"engine":"halmos","version":"1.0","command":"halmos"}]}]}
        """)
        val finding = parsed.finding(0)!!
        assertEquals("demonstrated", finding.getJSONObject("reproduction").getString("status"))
        assertEquals("call trace", finding.getJSONObject("reproduction").getString("trace"))
        assertEquals(42, finding.getJSONObject("traces_inputs_coverage_symbolic").getJSONObject("coverage").getInt("lines"))
        assertEquals("executed", finding.getJSONObject("traces_inputs_coverage_symbolic").getJSONObject("symbolic").getString("status"))
        assertEquals("executed", finding.getJSONObject("traces_inputs_coverage_symbolic").getJSONObject("invariants").getString("status"))
        assertEquals("halmos", finding.getJSONArray("evidence_provenance").getJSONObject(0).getString("engine"))
    }

    @Test fun unknownFieldsAndPartialReportsRemainForwardCompatible() {
        val parsed = report("""{"review_status":"unverified","future_field":{"value":true},"findings":[{"finding_id":"f-2","unknown_engine_field":"preserve raw JSON"}]}""")
        parsed.raw.put("review_status", REPORT_REVIEW_STATUS)
        assertEquals(REPORT_REVIEW_STATUS, parsed.reviewStatus)
        assertEquals("preserve raw JSON", parsed.finding(0)!!.getString("unknown_engine_field"))
        assertFalse(parsed.hasDemonstratedEvidence(parsed.finding(0)!!))
    }

    @Test fun missingEvidenceIsDistinctFromDemonstratedEvidence() {
        val parsed = report("""{"findings":[{"finding_id":"f-3","reproduction":{"status":"not demonstrated"}}]}""")
        val finding = parsed.finding(0)!!
        assertFalse(parsed.hasDemonstratedEvidence(finding))
        assertEquals("not demonstrated", finding.getJSONObject("reproduction").getString("status"))
    }

    @Test fun malformedEvidenceDoesNotBecomeAnExecutionClaim() {
        val parsed = report("""{"findings":[{"finding_id":"f-4","reproduction":"malformed"}]}""")
        val finding = parsed.finding(0)!!
        assertFalse(parsed.hasDemonstratedEvidence(finding))
        assertEquals("malformed", finding.getString("reproduction"))
    }
}
