package com.web3bughunter.android

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

private val Context.settings by preferencesDataStore("settings")
private val BASE = stringPreferencesKey("backend_url")
private const val HUMAN_REVIEW = "UNVERIFIED — HUMAN REVIEW REQUIRED"
private const val DEFAULT_BACKEND = "https://web3-bughunter.onrender.com"
const val API_CALL_TIMEOUT_SECONDS = 180L

/** Explicit client-side authorization state. It cannot become verified without both evidence and user confirmation. */
data class AuthorizationState(val evidence: String = "", val confirmed: Boolean = false) {
    val verified: Boolean get() = evidence.trim().isNotBlank() && confirmed
}

class Api(private val context: Context) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(API_CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .callTimeout(API_CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .build()

    suspend fun base(): String = context.settings.data.first()[BASE] ?: DEFAULT_BACKEND
    suspend fun saveBase(v: String) {
        val value = v.trim().trimEnd('/')
        require(value.startsWith("https://")) { "Backend URL must use HTTPS." }
        context.settings.edit { it[BASE] = value }
    }

    suspend fun call(path: String, method: String = "GET", body: JSONObject? = null): JSONObject = withContext(Dispatchers.IO) {
        val base = base().ifBlank { throw IllegalStateException("The production backend URL is not configured.") }
        require(base.startsWith("https://")) { "Backend URL must use HTTPS." }
        val requestBody = body?.toString()?.toRequestBody("application/json".toMediaType())
        val request = Request.Builder().url(base + path).method(method, if (method == "GET") null else requestBody).build()
        client.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                val serverMessage = runCatching { JSONObject(text).optString("error") }.getOrNull().orEmpty()
                val message = when {
                    response.code == 403 -> "This action is blocked until the required authorization/scope verification is complete."
                    response.code == 404 -> "The requested Web3 resource was not found."
                    response.code >= 500 -> "The research service could not complete that operation. Please try again."
                    serverMessage.isNotBlank() -> serverMessage
                    else -> "The request could not be completed (HTTP ${response.code})."
                }
                throw UserFacingException(message)
            }
            return@use JSONObject(text)
        }
    }
}

class UserFacingException(message: String): Exception(message)

data class Opp(val id: String, val name: String, val source: String, val status: String, val score: Double, val bounty: Double, val likelihood: Double, val difficulty: Double, val raw: JSONObject)
data class Target(val kind: String, val identifier: String, val sourceUrl: String, val address: String)
data class Finding(val id: String, val title: String, val severity: String, val confidence: Double, val description: String, val evidence: String, val status: String)

enum class Screen { OPPORTUNITIES, TARGET, ANALYZE, FINDINGS, QUEUE, HISTORY, SETTINGS }

class MainVm(private val api: Api): ViewModel() {
    var url by mutableStateOf("")
    var screen by mutableStateOf(Screen.OPPORTUNITIES)
    var busy by mutableStateOf(false)
    var error by mutableStateOf("")
    var notice by mutableStateOf("")
    var opps by mutableStateOf(listOf<Opp>())
    var selectedOpp by mutableStateOf<Opp?>(null)
    var targets by mutableStateOf(listOf<Target>())
    var scopeRules by mutableStateOf("")
    var exclusions by mutableStateOf(listOf<String>())
    var scopeEvidence by mutableStateOf("")
    var authorization by mutableStateOf(AuthorizationState())
    var acquiredPath by mutableStateOf("")
    var findings by mutableStateOf(listOf<Finding>())
    var report by mutableStateOf("")
    var queueText by mutableStateOf("")
    var historyText by mutableStateOf("")
    var selectedFinding by mutableStateOf<Finding?>(null)

    init { viewModelScope.launch { url = api.base() } }

    private fun run(block: suspend () -> Unit) = viewModelScope.launch {
        busy = true; error = ""; notice = ""
        try { block() } catch (e: Exception) { error = e.message ?: "The operation could not be completed." }
        finally { busy = false }
    }

    fun saveUrl(v: String) = run { api.saveBase(v); url = api.base(); notice = "Backend URL saved." }

    fun discover() = run {
        val d = api.call("/api/discover", "POST", JSONObject())
        opps = parseOpps(d.optJSONArray("opportunities"))
        notice = "Discovery completed: ${opps.size} opportunities available."
    }

    fun select(o: Opp) = run {
        api.call("/api/opportunities/${URLEncoder.encode(o.id, "UTF-8")}/select", "POST", JSONObject())
        selectedOpp = o
        authorization = AuthorizationState()
        scopeEvidence = ""
        loadPlanInternal(o)
        screen = Screen.TARGET
    }

    fun loadPlan() = selectedOpp?.let { run { loadPlanInternal(it) } }

    private suspend fun loadPlanInternal(o: Opp) {
        val evidence = buildString {
            append(o.raw.optString("scope_notes")); append('\n')
            append(o.raw.optJSONObject("metadata")?.toString().orEmpty()); append('\n')
            append(o.raw.optString("url"))
        }.trim()
        val d = api.call("/api/research/plan", "POST", JSONObject().put("opportunity", o.raw).put("public_evidence", evidence))
        val scope = d.optJSONObject("scope") ?: JSONObject()
        scopeEvidence = scope.optString("scope_evidence").ifBlank { evidence }
        scopeRules = scope.optString("rules")
        exclusions = jsonStrings(scope.optJSONArray("exclusions"))
        val a = d.optJSONArray("targets") ?: JSONArray()
        targets = (0 until a.length()).map { t ->
            val x = a.getJSONObject(it); Target(x.optString("kind"), x.optString("identifier"), x.optString("source_url"), x.optString("address"))
        }
        authorization = AuthorizationState(scopeEvidence, false)
    }

    fun setAuthorizationConfirmed(v: Boolean) {
        authorization = AuthorizationState(scopeEvidence, v)
    }

    fun acquire(target: Target) = run {
        if (!authorization.verified) throw UserFacingException("Verify the target scope and confirm authorization before acquiring source code.")
        val body = JSONObject().put("target", JSONObject().put("name", selectedOpp?.name ?: "authorized-target").put("source_url", target.sourceUrl).put("kind", target.kind).put("scope_evidence", scopeEvidence).put("authorized_scope_verified", true).put("addresses", JSONArray())).put("authorized_scope_verified", true)
        val d = api.call("/api/research/acquire", "POST", body)
        if (!d.optBoolean("ok")) throw UserFacingException(d.optString("reason", d.optString("error", "Target acquisition was blocked.")))
        acquiredPath = d.optString("path")
        notice = if (d.optBoolean("cached")) "Authorized target is already acquired on the research backend." else "Authorized target acquired successfully."
        screen = Screen.ANALYZE
    }

    fun analyze() = run {
        if (!authorization.verified) throw UserFacingException("Analysis is blocked. First review the scope evidence and explicitly confirm that the target is authorized.")
        if (acquiredPath.isBlank()) throw UserFacingException("Acquire an authorized repository before analysis.")
        val d = api.call("/api/research/analyze", "POST", JSONObject().put("source_dir", acquiredPath).put("protocol_name", selectedOpp?.name ?: "authorized-target").put("authorized_scope_verified", true).put("opportunity", selectedOpp?.raw ?: JSONObject()))
        findings = parseResearchFindings(d.optJSONArray("correlated_findings"))
        if (findings.isEmpty()) notice = "Analysis completed with no correlated findings." else notice = "Analysis completed. Findings remain unverified and require human review."
        screen = Screen.FINDINGS
    }

    fun fuzz() = run {
        if (!authorization.verified || acquiredPath.isBlank()) throw UserFacingException("Fuzzing is blocked until an authorized target has been acquired and scope verified.")
        val d = api.call("/api/security-tools/fuzz", "POST", JSONObject().put("source_dir", acquiredPath).put("framework", "auto").put("timeout", 180).put("authorized_scope_verified", true).put("findings", JSONArray(findings.map { JSONObject().put("id", it.id).put("title", it.title).put("severity", it.severity).put("description", it.description)) }))
        notice = if (d.optString("status").isNotBlank()) "Validation completed: ${d.optString("status")}." else "Fuzzing/validation completed."
    }

    fun duplicateCheck(f: Finding) = run {
        val d = api.call("/api/research/duplicate-check", "POST", JSONObject().put("finding", JSONObject().put("id", f.id).put("title", f.title).put("severity", f.severity).put("description", f.description).put("evidence", f.evidence)))
        val matches = d.optJSONArray("matches")?.length() ?: 0
        notice = if (matches == 0) "No similarity matches were returned. This is not a duplicate determination." else "$matches possible historical match(es) returned. Human review is required."
    }

    fun economic(f: Finding) = run {
        if (!authorization.verified) throw UserFacingException("Economic analysis requires verified authorization.")
        val d = api.call("/api/research/economic-analysis", "POST", JSONObject().put("finding", JSONObject().put("id", f.id).put("title", f.title).put("severity", f.severity).put("description", f.description)).put("authorized_scope_verified", true))
        notice = "Economic analysis completed. ${d.optString("status").ifBlank { "Review the result with the finding." }}"
    }

    fun generateReport() = run {
        val a = JSONArray(findings.map { JSONObject().put("id", it.id).put("title", it.title).put("severity", it.severity).put("confidence", it.confidence).put("description", it.description).put("evidence", JSONArray(listOf(it.evidence))).put("status", HUMAN_REVIEW) })
        val d = api.call("/api/generate-human-review-report", "POST", JSONObject().put("findings", a).put("opportunity", selectedOpp?.raw ?: JSONObject()))
        report = d.optJSONObject("report")?.toString(2) ?: d.toString(2)
        screen = Screen.FINDINGS
        notice = "Professional report generated for human review. Nothing has been submitted."
    }

    fun loadQueue() = run { queueText = api.call("/api/research/queue").toString(2) }
    fun loadHistory() = run { historyText = api.call("/api/hunting-history").toString(2) }

    private fun parseOpps(a: JSONArray?): List<Opp> = a?.let { (0 until it.length()).map { i ->
        val o = it.getJSONObject(i); Opp(o.optString("id"), o.optString("name"), o.optString("source"), o.optString("status"), o.optDouble("score"), o.optDouble("max_bounty_usd"), o.optDouble("likelihood"), o.optDouble("difficulty"), o)
    } } ?: emptyList()

    private fun parseResearchFindings(a: JSONArray?): List<Finding> = a?.let { (0 until it.length()).map { i ->
        val f = it.getJSONObject(i); Finding(f.optString("id"), f.optString("title", f.optString("vulnerability", "Finding")), f.optString("severity", "medium"), f.optDouble("confidence"), f.optString("description"), f.optJSONArray("evidence")?.toString().orEmpty(), HUMAN_REVIEW)
    } } ?: emptyList()

    private fun jsonStrings(a: JSONArray?): List<String> = a?.let { (0 until it.length()).map { i -> it.optString(i) } } ?: emptyList()
}

class MainActivity : ComponentActivity() {
    override fun onCreate(b: Bundle?) { super.onCreate(b); setContent { App(MainVm(Api(this))) } }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable fun App(vm: MainVm) {
    MaterialTheme {
        Scaffold(topBar = { TopAppBar(title = { Text("Web3 BugHunter", fontWeight = FontWeight.Bold) }) }) { padding ->
            Column(Modifier.padding(padding).fillMaxSize()) {
                if (vm.error.isNotBlank()) Text(vm.error, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(12.dp))
                if (vm.notice.isNotBlank()) Text(vm.notice, modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp))
                val screens = listOf(Screen.OPPORTUNITIES, Screen.TARGET, Screen.ANALYZE, Screen.FINDINGS, Screen.QUEUE, Screen.HISTORY, Screen.SETTINGS)
                ScrollableTabRow(selectedTabIndex = screens.indexOf(vm.screen)) { screens.forEach { s ->
                    Tab(vm.screen == s, onClick = { vm.screen = s }, text = { Text(s.name.lowercase().replace('_', ' ').replaceFirstChar { it.uppercase() }) })
                } }
                when (vm.screen) {
                    Screen.OPPORTUNITIES -> Opps(vm)
                    Screen.TARGET -> TargetScreen(vm)
                    Screen.ANALYZE -> AnalyzeScreen(vm)
                    Screen.FINDINGS -> FindingsScreen(vm)
                    Screen.QUEUE -> QueueScreen(vm)
                    Screen.HISTORY -> HistoryScreen(vm)
                    Screen.SETTINGS -> Settings(vm)
                }
            }
        }
    }
}

@Composable fun Opps(vm: MainVm) {
    Column(Modifier.padding(12.dp).fillMaxSize()) {
        Button(onClick = { vm.discover() }, enabled = !vm.busy, modifier = Modifier.fillMaxWidth()) { Text(if (vm.busy) "Discovering…" else "Discover & Rank") }
        Spacer(Modifier.height(8.dp))
        LazyColumn { items(vm.opps) { o -> Card(Modifier.fillMaxWidth().padding(vertical = 5.dp)) { Column(Modifier.padding(12.dp)) {
            Text(o.name, fontWeight = FontWeight.Bold); Text("${o.source.uppercase()} • ${o.status}")
            Text("Score ${o.score}/100 • max bounty $${o.bounty.toInt()}")
            Text("Likelihood ${(o.likelihood * 100).toInt()}% • difficulty ${(o.difficulty * 100).toInt()}%")
            Button(onClick = { vm.select(o) }, enabled = !vm.busy) { Text("Select & investigate") }
        } } } }
    }
}

@Composable fun TargetScreen(vm: MainVm) {
    Column(Modifier.padding(12.dp).fillMaxSize()) {
        Text("Target & authorization", style = MaterialTheme.typography.titleLarge)
        vm.selectedOpp?.let { Text(it.name, fontWeight = FontWeight.Bold) }
        Text("Public discovery is not authorization. Review the scope evidence, inclusions, rules and exclusions below.", modifier = Modifier.padding(vertical = 8.dp))
        if (vm.scopeEvidence.isNotBlank()) Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(12.dp)) { Text("Scope evidence", fontWeight = FontWeight.Bold); Text(vm.scopeEvidence) } }
        if (vm.scopeRules.isNotBlank()) Text("Rules: ${vm.scopeRules}", modifier = Modifier.padding(vertical = 6.dp))
        if (vm.exclusions.isNotEmpty()) Text("Exclusions: ${vm.exclusions.joinToString()}", modifier = Modifier.padding(vertical = 6.dp))
        Text("Authorized targets", fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
        if (vm.targets.isEmpty()) Text("No explicit repository or contract target was extracted from the available public evidence. Do not test until a valid authorized target is established.")
        LazyColumn { items(vm.targets) { t -> Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) { Column(Modifier.padding(10.dp)) {
            Text(t.identifier.ifBlank { t.address }, fontWeight = FontWeight.Bold); Text(t.kind)
            if (t.sourceUrl.isNotBlank()) Button(onClick = { vm.acquire(t) }, enabled = !vm.busy && vm.authorization.verified) { Text("Acquire authorized target") }
        } } } }
        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            Checkbox(checked = vm.authorization.confirmed, onCheckedChange = { vm.setAuthorizationConfirmed(it) }, enabled = vm.scopeEvidence.isNotBlank())
            Text("I have personally verified that the selected target is authorized and in scope, using the evidence above.")
        }
        Text(if (vm.authorization.verified) "Authorization state established for this client session." else "Analysis and acquisition remain blocked until explicit confirmation with scope evidence.", fontWeight = FontWeight.Bold)
    }
}

@Composable fun AnalyzeScreen(vm: MainVm) {
    Column(Modifier.padding(12.dp).fillMaxSize()) {
        Text("Authorized research", style = MaterialTheme.typography.titleLarge)
        Text("Acquired target: ${vm.acquiredPath.ifBlank { "none" }}")
        Text(HUMAN_REVIEW, fontWeight = FontWeight.Bold, modifier = Modifier.padding(vertical = 6.dp))
        Button(onClick = { vm.analyze() }, enabled = !vm.busy && vm.authorization.verified && vm.acquiredPath.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text(if (vm.busy) "Analyzing…" else "Analyze authorized target") }
        Spacer(Modifier.height(8.dp))
        Button(onClick = { vm.fuzz() }, enabled = !vm.busy && vm.authorization.verified && vm.acquiredPath.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Run bounded fuzz/validation") }
        Text("Security-tool analysis, protocol mapping, attack paths, economic analysis and bounded validation are performed by the existing backend research pipeline; Android only orchestrates it.", modifier = Modifier.padding(top = 10.dp))
    }
}

@Composable fun FindingsScreen(vm: MainVm) {
    Column(Modifier.padding(12.dp).fillMaxSize()) {
        Text("Findings & evidence", style = MaterialTheme.typography.titleLarge)
        Text(HUMAN_REVIEW, fontWeight = FontWeight.Bold)
        if (vm.findings.isNotEmpty()) {
            Button(onClick = { vm.generateReport() }, enabled = !vm.busy, modifier = Modifier.fillMaxWidth()) { Text("Generate professional human-review report") }
        }
        if (vm.report.isNotBlank()) Card(Modifier.fillMaxWidth().padding(vertical = 8.dp)) { Column(Modifier.padding(10.dp)) { Text("Report", fontWeight = FontWeight.Bold); Text(vm.report) } }
        LazyColumn { items(vm.findings) { f -> Card(onClick = { vm.selectedFinding = f }, modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp)) { Column(Modifier.padding(10.dp)) {
            Text(f.title, fontWeight = FontWeight.Bold); Text("${f.severity.uppercase()} • confidence ${(f.confidence * 100).toInt()}%"); Text(f.status)
        } } } }
        vm.selectedFinding?.let { f -> AlertDialog(onDismissRequest = { vm.selectedFinding = null }, confirmButton = { TextButton({ vm.selectedFinding = null }) { Text("Close") } }, title = { Text(f.title) }, text = { Column {
            Text(HUMAN_REVIEW, fontWeight = FontWeight.Bold); Text(f.description); Spacer(Modifier.height(8.dp)); Text("Evidence", fontWeight = FontWeight.Bold); Text(f.evidence)
            Row { TextButton(onClick = { vm.duplicateCheck(f) }) { Text("Check duplicates") }; TextButton(onClick = { vm.economic(f) }) { Text("Economic analysis") } }
        } }) }
    }
}

@Composable fun QueueScreen(vm: MainVm) { Column(Modifier.padding(12.dp)) { Text("Research queue", style = MaterialTheme.typography.titleLarge); Button(onClick = { vm.loadQueue() }, enabled = !vm.busy) { Text("Refresh queue") }; if (vm.queueText.isNotBlank()) Text(vm.queueText) } }
@Composable fun HistoryScreen(vm: MainVm) { Column(Modifier.padding(12.dp)) { Text("Hunting history", style = MaterialTheme.typography.titleLarge); Button(onClick = { vm.loadHistory() }, enabled = !vm.busy) { Text("Refresh history") }; if (vm.historyText.isNotBlank()) Text(vm.historyText) } }
@Composable fun Settings(vm: MainVm) { var u by remember(vm.url) { mutableStateOf(vm.url) }; Column(Modifier.padding(12.dp)) { Text("Backend", style = MaterialTheme.typography.titleLarge); Text("Production backend is HTTPS-only. Do not point this release client at localhost or an emulator service."); OutlinedTextField(u, { u = it }, label = { Text("HTTPS backend URL") }, modifier = Modifier.fillMaxWidth()); Spacer(Modifier.height(8.dp)); Button(onClick = { vm.saveUrl(u) }, enabled = !vm.busy, modifier = Modifier.fillMaxWidth()) { Text("Save backend URL") }; Spacer(Modifier.height(16.dp)); Text("Automatic bounty submission is disabled. Findings remain unverified and reports require human verification and manual submission.") } }
