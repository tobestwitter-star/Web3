package com.web3bughunter.android

import org.json.JSONArray
import org.json.JSONObject

const val REPORT_REVIEW_STATUS = "UNVERIFIED — HUMAN REVIEW REQUIRED"
const val REPORT_DUPLICATE_STATUS = "POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED"

data class ProfessionalReport(val raw: JSONObject) {
    val reviewStatus: String get() = raw.optString("review_status", REPORT_REVIEW_STATUS)
    val doNotAutoSubmit: Boolean get() = raw.optBoolean("do_not_auto_submit", true)
    val humanReviewOnly: Boolean get() = raw.optBoolean("human_review_only", true)
    val findings: JSONArray get() = raw.optJSONArray("findings") ?: JSONArray()
    val scopeAndAuthorization: JSONObject get() = raw.optJSONObject("scope_and_authorization") ?: JSONObject()
    val limitations: JSONArray get() = raw.optJSONArray("limitations") ?: JSONArray()

    fun finding(index: Int): JSONObject? = findings.optJSONObject(index)

    fun findingStatus(finding: JSONObject): String =
        finding.optString("review_status", reviewStatus)

    fun duplicateStatus(finding: JSONObject): String =
        finding.optString("duplicate_status", "")

    fun hasDemonstratedEvidence(finding: JSONObject): Boolean {
        val evidence = finding.optJSONArray("engine_evidence")
        val reproduction = finding.optJSONObject("reproduction")
        val execution = finding.optJSONArray("execution_metadata")
        return (evidence != null && evidence.length() > 0) ||
            (reproduction != null && reproduction.length() > 0) ||
            (execution != null && execution.length() > 0)
    }
}

fun JSONObject.toProfessionalReport(): ProfessionalReport = ProfessionalReport(this)
