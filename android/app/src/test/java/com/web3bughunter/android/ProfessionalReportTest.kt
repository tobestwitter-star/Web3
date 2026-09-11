package com.web3bughunter.android

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ProfessionalReportTest {
    private fun completeReport(): JSONObject {
        val engineEvidence = listOf(
            mapOf("engine" to "slither", "raw_evidence" to listOf("structured slither evidence")),
            mapOf("engine" to "forge", "raw_evidence" to listOf("structured forge evidence"))
        )
        val finding = mapOf(
            "finding_id" to "f-1",
            "title" to "Reentrancy",
            "severity" to "high",
            "confidence" to 0.91,
            "review_status" to REPORT_REVIEW_STATUS,
            "duplicate_status" to REPORT_DUPLICATE_STATUS,
            "engine_evidence" to engineEvidence,
            "engine_provenance" to listOf(mapOf("engine" to "forge", "version" to "1.0", "command" to "forge test")),
            "execution_metadata" to listOf(mapOf("status" to "executed", "returncode" to 0, "command" to "forge test")),
            "reproduction" to mapOf("status" to "demonstrated", "evidence" to mapOf("trace" to "call trace", "inputs" to mapOf("amount" to 1))),
            "traces_inputs_coverage_symbolic" to mapOf("trace" to "call trace", "inputs" to mapOf("amount" to 1), "coverage" to mapOf("lines" to 42), "symbolic" to mapOf("status" to "executed"), "invariants" to mapOf("status" to "executed")),
            "evidence_provenance" to listOf(mapOf("engine" to "forge", "sha256" to "abc")),
            "historical_context" to listOf(mapOf("match_type" to "semantic_similarity_lead", "similarity" to 0.84)),
            "economic_impact" to mapOf("estimated_loss_usd" to 125000),
            "remediation" to "Update state before external interaction.",
            "limitations" to listOf("Requires independent human reproduction.")
        )
        return JSONObject(mapOf(
            "report_version" to "1.1",
            "review_status" to REPORT_REVIEW_STATUS,
            "do_not_auto_submit" to true,
            "human_review_only" to true,
            "scope_and_authorization" to mapOf("scope" to "authorized scope", "authorization" to mapOf("confirmed" to true)),
            "limitations" to listOf("Missing evidence is not inferred or fabricated."),
            "findings" to listOf(finding)
        ))
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
        assertEquals("abc", finding.getJSONArray("evidence_provenance").getJSONObject(0).getString("sha256"))
    }

    @Test fun unknownFieldsAndPartialReportsRemainForwardCompatible() {
        val report = JSONObject(mapOf(
            "review_status" to REPORT_REVIEW_STATUS,
            "future_field" to mapOf("value" to true),
            "findings" to listOf(mapOf("finding_id" to "f-2", "severity" to "medium", "unknown_engine_field" to "preserve raw JSON"))
        )).toProfessionalReport()
        assertEquals(REPORT_REVIEW_STATUS, report.reviewStatus)
        assertEquals("preserve raw JSON", report.finding(0)!!.getString("unknown_engine_field"))
        assertFalse(report.hasDemonstratedEvidence(report.finding(0)!!))
    }

    @Test fun missingEvidenceIsDistinctFromDemonstratedEvidence() {
        val report = JSONObject(mapOf(
            "findings" to listOf(mapOf("finding_id" to "f-3", "reproduction" to mapOf("status" to "not demonstrated")))
        )).toProfessionalReport()
        assertFalse(report.hasDemonstratedEvidence(report.finding(0)!!))
        assertEquals("not demonstrated", report.finding(0)!!.getJSONObject("reproduction").getString("status"))
    }

    @Test fun malformedEvidenceDoesNotBecomeAnExecutionClaim() {
        val report = JSONObject(mapOf(
            "findings" to listOf(mapOf("finding_id" to "f-4", "reproduction" to "malformed"))
        )).toProfessionalReport()
        assertFalse(report.hasDemonstratedEvidence(report.finding(0)!!))
        assertEquals("malformed", report.finding(0)!!.getString("reproduction"))
    }
}
