package com.web3bughunter.android

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
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import android.content.Context
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject

private val Context.settings by preferencesDataStore("settings")
private val BASE = stringPreferencesKey("backend_url")

class Api(private val context: Context) {
    private val client = OkHttpClient()
    suspend fun base(): String = context.settings.data.first()[BASE] ?: ""
    suspend fun saveBase(v: String) { context.settings.edit { it[BASE] = v.trim().trimEnd('/') } }
    suspend fun call(path: String, method: String = "GET", body: JSONObject? = null): JSONObject = withContext(Dispatchers.IO) {
        val base = base().ifBlank { throw IllegalStateException("Configure the HTTPS backend URL in Settings") }
        require(base.startsWith("https://")) { "Backend URL must use HTTPS" }
        val b = body?.toString()?.toRequestBody("application/json".toMediaType())
        val req = Request.Builder().url(base + path).method(method, if (method == "GET") null else b).build()
        client.newCall(req).execute().use { r -> val text = r.body?.string().orEmpty(); if (!r.isSuccessful) throw IllegalStateException("HTTP ${r.code}: $text"); JSONObject(text) }
    }
}

data class Opp(val id:String,val name:String,val source:String,val status:String,val score:Double,val bounty:Double,val likelihood:Double,val difficulty:Double)
data class Finding(val id:String,val title:String,val severity:String,val confidence:Double,val report:String,val status:String)

class MainVm(private val api: Api): ViewModel() {
    var url by mutableStateOf(""); var tab by mutableStateOf("opportunities"); var busy by mutableStateOf(false); var error by mutableStateOf(""); var opps by mutableStateOf(listOf<Opp>()); var findings by mutableStateOf(listOf<Finding>()); var selected by mutableStateOf<Finding?>(null)
    init { viewModelScope.launch { url = api.base() } }
    fun saveUrl(v:String) = viewModelScope.launch { error=""; try { api.saveBase(v); url=api.base() } catch(e:Exception){error=e.message.orEmpty()} }
    fun discover() = run { val d=api.call("/api/discover","POST",JSONObject()); val a=d.optJSONArray("opportunities")?:JSONArray(); opps=(0 until a.length()).map { val o=a.getJSONObject(it); Opp(o.optString("id"),o.optString("name"),o.optString("source"),o.optString("status"),o.optDouble("score"),o.optDouble("max_bounty_usd"),o.optDouble("likelihood"),o.optDouble("difficulty")) } }
    fun select(o:Opp) = run { api.call("/api/opportunities/${java.net.URLEncoder.encode(o.id,"UTF-8")}/select","POST",JSONObject()) }
    fun analyze(name:String,code:String) = run { require(name.isNotBlank() && code.isNotBlank()){"Protocol name and authorized source are required"}; val d=api.call("/api/analyze-advanced","POST",JSONObject().put("protocol_name",name).put("code",code)); val a=d.optJSONArray("detailed_reports")?:JSONArray(); findings=(0 until a.length()).map { val f=a.getJSONObject(it); Finding(f.optString("finding_id"),f.optString("vulnerability"),f.optString("severity"),f.optDouble("confidence"),f.optString("detailed_report"),f.optString("status")) }; tab="findings" }
    private fun run(block:suspend()->Unit) { viewModelScope.launch { busy=true; error=""; try { block() } catch(e:Exception){error=e.message ?: "Request failed"} finally {busy=false} } }
}

class MainActivity: ComponentActivity() { override fun onCreate(b:Bundle?){super.onCreate(b); setContent{ App(MainVm(Api(this))) }} }

@Composable fun App(vm:MainVm) { MaterialTheme { Scaffold(topBar={TopAppBar(title={Text("Web3 BugHunter",fontWeight=FontWeight.Bold)})}) { p-> Column(Modifier.padding(p).fillMaxSize()){ if(vm.error.isNotBlank()) Text(vm.error, color=MaterialTheme.colorScheme.error, modifier=Modifier.padding(12.dp)); TabRow(selectedTabIndex=listOf("opportunities","analyze","findings","settings").indexOf(vm.tab)){ listOf("opportunities","analyze","findings","settings").forEachIndexed{ i,t-> Tab(i==listOf("opportunities","analyze","findings","settings").indexOf(vm.tab),onClick={vm.tab=t},text={Text(t.replaceFirstChar{it.uppercase()})}) } }; when(vm.tab){"opportunities"->Opps(vm);"analyze"->Analyze(vm);"findings"->Findings(vm);else->Settings(vm)} } } } }

@Composable fun Opps(vm:MainVm){ Column(Modifier.padding(12.dp)){ Button(onClick={vm.discover()},enabled=!vm.busy,modifier=Modifier.fillMaxWidth()){Text(if(vm.busy)"Loading…" else "Discover & Rank")}; Spacer(Modifier.height(8.dp)); LazyColumn{items(vm.opps){o-> Card(Modifier.fillMaxWidth().padding(vertical=5.dp)){Column(Modifier.padding(12.dp)){Text(o.name,fontWeight=FontWeight.Bold);Text("${o.source.uppercase()} • ${o.status}");Text("Score ${o.score}/100 • max bounty $${o.bounty.toInt()}");Text("Likelihood ${(o.likelihood*100).toInt()}% • difficulty ${(o.difficulty*100).toInt()}%");Button(onClick={vm.select(o)}){Text("Select for investigation")}}}}} } }

@Composable fun Analyze(vm:MainVm){ var name by remember{mutableStateOf("")};var code by remember{mutableStateOf("")};Column(Modifier.padding(12.dp)){Text("Authorized protocol analysis",style=MaterialTheme.typography.titleLarge);Text("UNVERIFIED — HUMAN REVIEW REQUIRED",fontWeight=FontWeight.Bold);Text("Only analyze targets whose scope you have verified. Nothing is submitted automatically.",modifier=Modifier.padding(vertical=8.dp));OutlinedTextField(name,{name=it},label={Text("Protocol name")},modifier=Modifier.fillMaxWidth());Spacer(Modifier.height(8.dp));OutlinedTextField(code,{code=it},label={Text("Authorized Solidity/source code")},modifier=Modifier.fillMaxWidth().height(220.dp));Spacer(Modifier.height(8.dp));Button(onClick={vm.analyze(name,code)},enabled=!vm.busy,modifier=Modifier.fillMaxWidth()){Text(if(vm.busy)"Analyzing…" else "Run analysis")}}
}

@Composable fun Findings(vm:MainVm){Column(Modifier.padding(12.dp)){Text("Findings — Human Verification Queue",style=MaterialTheme.typography.titleLarge);Text("UNVERIFIED — HUMAN REVIEW REQUIRED",fontWeight=FontWeight.Bold);LazyColumn{items(vm.findings){f->Card(Modifier.fillMaxWidth().padding(vertical=5.dp),onClick={vm.selected=f}){Column(Modifier.padding(12.dp)){Text(f.title,fontWeight=FontWeight.Bold);Text("${f.severity.uppercase()} • confidence ${(f.confidence*100).toInt()}%");Text(f.status)}}}}};vm.selected?.let{f->AlertDialog(onDismissRequest={vm.selected=null},confirmButton={TextButton({vm.selected=null}){Text("Close")}},title={Text(f.title)},text={Column{Text("UNVERIFIED — HUMAN REVIEW REQUIRED",fontWeight=FontWeight.Bold);Text(f.report)}})}}

@Composable fun Settings(vm:MainVm){var u by remember(vm.url){mutableStateOf(vm.url)};Column(Modifier.padding(12.dp)){Text("Backend",style=MaterialTheme.typography.titleLarge);Text("Use the deployed HTTPS Flask backend; configuration is stored locally on this device.");OutlinedTextField(u,{u=it},label={Text("HTTPS backend URL")},modifier=Modifier.fillMaxWidth());Spacer(Modifier.height(8.dp));Button(onClick={vm.saveUrl(u)},modifier=Modifier.fillMaxWidth()){Text("Save")};Spacer(Modifier.height(16.dp));Text("Automatic bounty submission is disabled. Reports require human verification and manual submission.")}}
