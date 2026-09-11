package com.web3bughunter.android

import org.json.JSONArray
import org.json.JSONObject

const val REPORT_REVIEW_STATUS = "UNVERIFIED — HUMAN REVIEW REQUIRED"
const val REPORT_DUPLICATE_STATUS = "POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED"

data class ProfessionalReport(val raw: JSONObject) {
    val reviewStatus: String get() = raw.optString("review_status").ifBlank { REPORT_REVIEW_STATUS }
    val doNotAutoSubmit: Boolean get() = raw.optBoolean("do_not_auto_submit", true)
    val humanReviewOnly: Boolean get() = raw.optBoolean("human_review_only", true)
    val findings: JSONArray get() = raw.optJSONArray("findings") ?: JSONArray()
    val scopeAndAuthorization: JSONObject get() = raw.optJSONObject("scope_and_authorization") ?: JSONObject()
    val limitations: JSONArray get() = raw.optJSONArray("limitations") ?: JSONArray()

    fun finding(index: Int): JSONObject? = findings.optJSONObject(index)

    fun findingStatus(finding: JSONObject): String =
        finding.optString("review_status").ifBlank { reviewStatus }

    fun duplicateStatus(finding: JSONObject): String = finding.optString("duplicate_status")

    fun hasDemonstratedEvidence(finding: JSONObject): Boolean {
        val engineEvidence = finding.optJSONArray("engine_evidence")
        val reproduction = finding.optJSONObject("reproduction")
        val execution = finding.optJSONArray("execution_metadata")
        val reproductionDemonstrated = reproduction?.optString("status")?.equals("demonstrated", ignoreCase = true) == true
        val executionDemonstrated = (0 until (execution?.length() ?: 0)).any { execution.optJSONObject(it)?.optString("status")?.equals("executed", ignoreCase = true) == true }
        return (engineEvidence != null && engineEvidence.length() > 0) || reproductionDemonstrated || executionDemonstrated
    }
}

fun JSONObject.toProfessionalReport(): ProfessionalReport = ProfessionalReport(this)
