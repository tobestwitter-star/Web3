package com.web3bughunter.android

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ProfessionalReportTest {
    private fun completeReport(): JSONObject = JSONObject(
        """
        {
          "report_version":"1.1",
          "review_status":"UNVERIFIED — HUMAN REVIEW REQUIRED",
          "do_not_auto_submit":true,
          "human_review_only":true,
          "scope_and_authorization":{"scope":"authorized scope","authorization":{"confirmed":true}},
          "limitations":["Missing evidence is not inferred or fabricated."],
          "findings":[{
            "finding_id":"f-1",
            "title":"Reentrancy",
            "severity":"high",
            "confidence":0.91,
            "review_status":"UNVERIFIED — HUMAN REVIEW REQUIRED",
            "duplicate_status":"POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED",
            "engine_evidence":[{"engine":"slither","raw_evidence":["structured slither evidence"]},{"engine":"forge","raw_evidence":["structured forge evidence"]}],
            "engine_provenance":[{"engine":"forge","version":"1.0","command":"forge test"}],
            "execution_metadata":[{"status":"executed","returncode":0,"command":"forge test"}],
            "reproduction":{"status":"demonstrated","evidence":{"trace":"call trace","inputs":{"amount":1}}},
            "traces_inputs_coverage_symbolic":{"trace":"call trace","inputs":{"amount":1},"coverage":{"lines":42},"symbolic":{"status":"executed"},"invariants":{"status":"executed"}},
            "evidence_provenance":[{"engine":"forge","sha256":"abc"}],
            "historical_context":[{"match_type":"semantic_similarity_lead","similarity":0.84}],
            "economic_impact":{"estimated_loss_usd":125000},
            "remediation":"Update state before external interaction.",
            "limitations":["Requires independent human reproduction."]
          }]
        }
        """.trimIndent()
    )

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
        val report = JSONObject("""{"review_status":"UNVERIFIED — HUMAN REVIEW REQUIRED","future_field":{"value":true},"findings":[{"finding_id":"f-2","severity":"medium","unknown_engine_field":"preserve raw JSON"}]}""").toProfessionalReport()
        assertEquals(REPORT_REVIEW_STATUS, report.reviewStatus)
        assertEquals("preserve raw JSON", report.finding(0)!!.getString("unknown_engine_field"))
        assertFalse(report.hasDemonstratedEvidence(report.finding(0)!!))
    }

    @Test fun missingEvidenceIsDistinctFromDemonstratedEvidence() {
        val finding = JSONObject("""{"finding_id":"f-3","reproduction":{"status":"not demonstrated","evidence":null}}""")
        val report = JSONObject().put("findings", JSONArray().put(finding)).toProfessionalReport()
        assertFalse(report.hasDemonstratedEvidence(report.finding(0)!!))
        assertEquals("not demonstrated", report.finding(0)!!.getJSONObject("reproduction").getString("status"))
    }

    @Test fun malformedEvidenceDoesNotBecomeAnExecutionClaim() {
        val finding = JSONObject("""{"finding_id":"f-4","reproduction":"malformed"}""")
        val report = JSONObject().put("findings", JSONArray().put(finding)).toProfessionalReport()
        assertFalse(report.hasDemonstratedEvidence(report.finding(0)!!))
        assertEquals("malformed", report.finding(0)!!.getString("reproduction"))
    }
}
