import os
from flask import Flask, jsonify, request
from advanced_web3_analyzer import AdvancedWeb3Analyzer, generate_detailed_report
from bounty_engine import OpportunityStore, PublicProgramDiscovery, build_report
from security_toolchain import SecurityToolchain
from research_pipeline import ResearchPipeline
app=Flask(__name__); store=OpportunityStore(os.environ.get('BUGHUNTER_DB','bughunter.db')); discovery=PublicProgramDiscovery(); toolchain=SecurityToolchain(); research=ResearchPipeline()
def fd(f): return {'id':f.id,'type':f.vulnerability_type,'severity':f.severity,'category':f.category,'location':f.location,'description':f.description,'poc':f.proof_of_concept,'impact':f.economic_impact,'confidence':f.confidence,'bounty_low':f.bounty_estimate_low,'bounty_high':f.bounty_estimate_high,'requires_verification':True,'status':'UNVERIFIED — HUMAN REVIEW REQUIRED'}
def _refresh(sources=None):
    found,diagnostics=discovery.discover_public_indexes(sources)
    for o in found: store.upsert(o)
    return found,diagnostics
@app.get('/api/health')
def health(): return jsonify({'status':'Web3 BugHunter running','human_review_required':True,'auto_submission':False,'live_public_discovery':True})
@app.get('/api/security-tools')
def security_tools(): return jsonify({'tools':toolchain.inventory(),'license_policy':'Only use tools according to their licenses; no tool is downloaded or installed automatically.'})
@app.post('/api/security-tools/analyze')
def security_tools_analyze():
    data=request.get_json(silent=True) or {}; source_dir=data.get('source_dir'); authorized=bool(data.get('authorized_scope_verified'))
    if not source_dir:return jsonify({'error':'source_dir is required'}),400
    if not authorized:return jsonify({'error':'authorized_scope_verified must be true before external analyzers can run'}),403
    return jsonify(toolchain.analyze(source_dir,data.get('tools'),int(data.get('timeout',120))))
@app.post('/api/research/plan')
def research_plan():
    data=request.get_json(silent=True) or {}; opp=data.get('opportunity') or {}; return jsonify(research.plan(opp,str(data.get('public_evidence',''))))
@app.post('/api/research/acquire')
def research_acquire():
    data=request.get_json(silent=True) or {}; tdata=data.get('target') or {}; authorized=bool(data.get('authorized_scope_verified'))
    from research_pipeline import Target
    target=Target(str(tdata.get('name','target')),str(tdata.get('source_url','')),str(tdata.get('kind','repository')),str(tdata.get('branch','')),authorized,str(tdata.get('scope_evidence','')),tdata.get('addresses',[]),tdata.get('contracts',[]),tdata.get('assets',[]))
    return jsonify(research.acquirer.clone_public_repo(target,str(data.get('workspace') or os.environ.get('RESEARCH_WORKSPACE','research-workspace')),authorized))
@app.post('/api/research/analyze')
def research_analyze():
    data=request.get_json(silent=True) or {}
    if not data.get('authorized_scope_verified'): return jsonify({'error':'authorized_scope_verified must be true before research analysis'}),403
    return jsonify(research.analyze_local(str(data.get('source_dir','')),str(data.get('protocol_name','authorized-target')),data.get('source_code'),True,data.get('tools')))
@app.get('/api/opportunities')
def opportunities(): return jsonify({'opportunities':store.list(min(int(request.args.get('limit',50)),200)),'workflow':'Discover → Evaluate → Rank → Select → Scope → Acquire → Analyze → Correlate → Validate → Report → Human Review → Manual Submission'})
@app.post('/api/discover')
def discover():
    data=request.get_json(silent=True) or {}
    if data.get('programs') is not None: found=discovery.discover_from_json(data.get('programs'),data.get('source','manual-import')); diagnostics=[{'source':data.get('source','manual-import'),'mode':'import','entries':len(found)}]
    else: found,diagnostics=_refresh(data.get('sources'))
    for o in found: store.upsert(o)
    return jsonify({'status':'discovery_complete','count':len(found),'diagnostics':diagnostics,'opportunities':store.list(100)})
@app.post('/api/opportunities/refresh')
def refresh_opportunities():
    data=request.get_json(silent=True) or {}; found,diagnostics=_refresh(data.get('sources')); return jsonify({'status':'live_discovery_complete','discovered':len(found),'diagnostics':diagnostics,'opportunities':store.list(100)})
@app.get('/api/opportunities/ranked')
def ranked_opportunities(): return jsonify({'opportunities':store.list(min(int(request.args.get('limit',50)),200)),'selection_basis':'Expected reward + valid-finding likelihood + severity + attack surface + source availability + difficulty + research-time efficiency + competition risk'})
@app.post('/api/opportunities/select-best')
def select_best():
    found,diagnostics=_refresh(); ranked=store.list(200); actionable=[o for o in ranked if o.get('status')=='active' and o.get('scope_size',0)>0]
    if not actionable:return jsonify({'status':'no_actionable_opportunity','discovered':len(found),'diagnostics':diagnostics,'human_review_required':True}),404
    best=actionable[0];store.set_hunt_status(best['id'],'Investigating','Automatically selected as highest expected-value actionable public opportunity. Scope must still be human-verified before testing.')
    return jsonify({'status':'selected','opportunity':best,'discovered':len(found),'diagnostics':diagnostics,'human_review_required':True,'authorization_note':'Public discovery is not authorization; verify program scope and rules before investigation.'})
@app.post('/api/opportunities/<opportunity_id>/select')
def select_opportunity(opportunity_id):
    match=next((o for o in store.list(200) if o['id']==opportunity_id),None)
    if not match:return jsonify({'error':'Opportunity not found'}),404
    store.set_hunt_status(opportunity_id,'Investigating','Selected by expected-value ranking; scope requires human verification before testing.');return jsonify({'status':'selected','opportunity':match,'human_review_required':True})
@app.get('/api/hunting-history')
def hunting_history():return jsonify({'history':store.history()})
@app.post('/api/hunting-history/<opportunity_id>')
def update_hunt(opportunity_id):
    data=request.get_json(silent=True) or {};status=data.get('status','Needs Research');allowed={'Investigating','Needs Research','Rejected','False Positive','Verified','Report Ready','Submitted','Duplicate'}
    if status not in allowed:return jsonify({'error':'Invalid hunt status'}),400
    store.set_hunt_status(opportunity_id,status,str(data.get('notes','')),int(data.get('finding_count',0)));return jsonify({'status':'updated','opportunity_id':opportunity_id,'hunt_status':status})
@app.post('/api/analyze-advanced')
def analyze_advanced():
    data=request.get_json(silent=True) or {};code=data.get('code');name=data.get('protocol_name')
    if not code or not name:return jsonify({'error':'Missing protocol_code or protocol_name'}),400
    findings=AdvancedWeb3Analyzer().analyze_protocol(code,name);reports=[]
    for f in findings:reports.append({'finding_id':f.id,'vulnerability':f.vulnerability_type,'severity':f.severity,'confidence':f.confidence,'estimated_bounty':{'low':f.bounty_estimate_low,'high':f.bounty_estimate_high},'detailed_report':generate_detailed_report(f),'requires_manual_verification':True,'status':'UNVERIFIED — HUMAN REVIEW REQUIRED','learning_value':f.learning_value})
    return jsonify({'status':'analysis_complete','protocol':name,'findings_count':len(findings),'findings':[fd(f) for f in findings],'detailed_reports':reports,'next_step':'Review, reproduce, and manually verify before submission.'})
@app.post('/api/generate-human-review-report')
def generate_human_review_report():
    data=request.get_json(silent=True) or {};return jsonify({'status':'report_ready_for_human_review','report':build_report(data.get('findings',[]),data.get('opportunity',{}))})
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.environ.get('PORT',8080)),debug=False)
