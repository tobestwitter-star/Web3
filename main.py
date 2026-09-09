import os
from flask import Flask,jsonify,request
from advanced_web3_analyzer import AdvancedWeb3Analyzer,generate_detailed_report
from bounty_engine import OpportunityStore,PublicProgramDiscovery,build_report
from security_toolchain import SecurityToolchain
from research_pipeline import ResearchPipeline
from target_resolution import TargetMap
app=Flask(__name__);store=OpportunityStore(os.environ.get('BUGHUNTER_DB','bughunter.db'));discovery=PublicProgramDiscovery();toolchain=SecurityToolchain();research=ResearchPipeline()
def fd(f):return {'id':f.id,'type':f.vulnerability_type,'severity':f.severity,'category':f.category,'location':f.location,'description':f.description,'poc':f.proof_of_concept,'impact':f.economic_impact,'confidence':f.confidence,'bounty_low':f.bounty_estimate_low,'bounty_high':f.bounty_estimate_high,'requires_verification':True,'status':'UNVERIFIED — HUMAN REVIEW REQUIRED'}
def _refresh(sources=None):
 found,diagnostics=discovery.discover_public_indexes(sources)
 for o in found:store.upsert(o)
 return found,diagnostics
@app.get('/api/health')
def health():return jsonify({'status':'Web3 BugHunter running','human_review_required':True,'auto_submission':False,'live_public_discovery':True})
@app.get('/api/security-tools')
def security_tools():return jsonify({'tools':toolchain.inventory(),'license_policy':'Use tools according to their licenses; no automatic installation.'})
@app.post('/api/security-tools/analyze')
def security_tools_analyze():
 d=request.get_json(silent=True) or {};src=d.get('source_dir')
 if not src:return jsonify({'error':'source_dir is required'}),400
 if not d.get('authorized_scope_verified'):return jsonify({'error':'authorized_scope_verified must be true'}),403
 return jsonify(toolchain.analyze(src,d.get('tools'),int(d.get('timeout',120))))
@app.post('/api/security-tools/fuzz')
def security_tools_fuzz():
 d=request.get_json(silent=True) or {}
 if not d.get('source_dir'):return jsonify({'error':'source_dir is required'}),400
 if not d.get('authorized_scope_verified'):return jsonify({'error':'authorized_scope_verified must be true'}),403
 return jsonify(toolchain.fuzz(str(d['source_dir']),True,str(d.get('framework','auto')),int(d.get('timeout',180))))
@app.post('/api/research/plan')
def research_plan():
 d=request.get_json(silent=True) or {};return jsonify(research.plan(d.get('opportunity') or {},str(d.get('public_evidence',''))))
@app.post('/api/research/resolve')
def research_resolve():
 d=request.get_json(silent=True) or {};op=d.get('opportunity') or {};e=str(d.get('public_evidence',''));scope=research.scope.resolve(op,e);build=research.build.detect(str(d.get('source_dir',''))) if d.get('source_dir') else {'primary':None,'detected':[],'not_run':True};return jsonify(TargetMap().build(scope,build))
@app.post('/api/research/acquire')
def research_acquire():
 d=request.get_json(silent=True) or {};t=d.get('target') or {};authorized=bool(d.get('authorized_scope_verified'));from research_pipeline import Target
 target=Target(str(t.get('name','target')),str(t.get('source_url','')),str(t.get('kind','repository')),str(t.get('branch','')),authorized,str(t.get('scope_evidence','')),t.get('addresses',[]),t.get('contracts',[]),t.get('assets',[]));return jsonify(research.acquirer.clone_public_repo(target,str(d.get('workspace') or os.environ.get('RESEARCH_WORKSPACE','research-workspace')),authorized))
@app.post('/api/research/analyze')
def research_analyze():
 d=request.get_json(silent=True) or {}
 if not d.get('authorized_scope_verified'):return jsonify({'error':'authorized_scope_verified must be true'}),403
 return jsonify(research.analyze_local(str(d.get('source_dir','')),str(d.get('protocol_name','authorized-target')),d.get('source_code'),True,d.get('tools'),d.get('opportunity')))
@app.get('/api/research/history-leads')
def research_history_leads():
 d=request.args;return jsonify({'search_leads':research.history.search_urls(d.get('title',''),d.get('category','')), 'note':'Public-search leads only; similarity is not a duplicate determination.'})
@app.post('/api/research/duplicate-check')
def research_duplicate_check():
 d=request.get_json(silent=True) or {};return jsonify({'matches':research.history.compare(d.get('finding') or {},d.get('historical') or []),'status':'POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED'})
@app.get('/api/opportunities')
def opportunities():return jsonify({'opportunities':store.list(min(int(request.args.get('limit',50)),200)),'workflow':'Discover → Evaluate → Rank → Select → Scope → Acquire → Map → Analyze → Validate → Report → Human Review → Manual Submission'})
@app.post('/api/discover')
def discover():
 d=request.get_json(silent=True) or {};found=discovery.discover_from_json(d.get('programs'),d.get('source','manual-import')) if d.get('programs') is not None else _refresh(d.get('sources'))[0]
 for o in found:store.upsert(o)
 return jsonify({'status':'discovery_complete','count':len(found),'opportunities':store.list(100)})
@app.post('/api/opportunities/refresh')
def refresh_opportunities():
 found,diagnostics=_refresh((request.get_json(silent=True) or {}).get('sources'));return jsonify({'status':'live_discovery_complete','discovered':len(found),'diagnostics':diagnostics,'opportunities':store.list(100)})
@app.get('/api/opportunities/ranked')
def ranked_opportunities():return jsonify({'opportunities':store.list(min(int(request.args.get('limit',50)),200)),'selection_basis':'Expected reward + finding likelihood + severity + attack surface + difficulty + research-time efficiency + competition risk'})
@app.post('/api/opportunities/select-best')
def select_best():
 found,diagnostics=_refresh();ranked=store.list(200);actionable=[o for o in ranked if o.get('status')=='active' and o.get('scope_size',0)>0]
 if not actionable:return jsonify({'status':'no_actionable_opportunity','discovered':len(found),'diagnostics':diagnostics,'human_review_required':True}),404
 best=actionable[0];store.set_hunt_status(best['id'],'Investigating','Highest expected-value public opportunity; scope must be human-verified before testing.');return jsonify({'status':'selected','opportunity':best,'discovered':len(found),'diagnostics':diagnostics,'human_review_required':True,'authorization_note':'Public discovery is not authorization.'})
@app.post('/api/opportunities/<opportunity_id>/select')
def select_opportunity(opportunity_id):
 match=next((o for o in store.list(200) if o['id']==opportunity_id),None)
 if not match:return jsonify({'error':'Opportunity not found'}),404
 store.set_hunt_status(opportunity_id,'Investigating','Selected by ranking; scope requires human verification.');return jsonify({'status':'selected','opportunity':match,'human_review_required':True})
@app.get('/api/hunting-history')
def hunting_history():return jsonify({'history':store.history()})
@app.post('/api/hunting-history/<opportunity_id>')
def update_hunt(opportunity_id):
 d=request.get_json(silent=True) or {};status=d.get('status','Needs Research');allowed={'Investigating','Needs Research','Rejected','False Positive','Verified','Report Ready','Submitted','Duplicate'}
 if status not in allowed:return jsonify({'error':'Invalid hunt status'}),400
 store.set_hunt_status(opportunity_id,status,str(d.get('notes','')),int(d.get('finding_count',0)));return jsonify({'status':'updated','opportunity_id':opportunity_id,'hunt_status':status})
@app.post('/api/analyze-advanced')
def analyze_advanced():
 d=request.get_json(silent=True) or {};code=d.get('code');name=d.get('protocol_name')
 if not code or not name:return jsonify({'error':'Missing protocol_code or protocol_name'}),400
 findings=AdvancedWeb3Analyzer().analyze_protocol(code,name);reports=[{'finding_id':f.id,'vulnerability':f.vulnerability_type,'severity':f.severity,'confidence':f.confidence,'estimated_bounty':{'low':f.bounty_estimate_low,'high':f.bounty_estimate_high},'detailed_report':generate_detailed_report(f),'requires_manual_verification':True,'status':'UNVERIFIED — HUMAN REVIEW REQUIRED','learning_value':f.learning_value} for f in findings];return jsonify({'status':'analysis_complete','protocol':name,'findings_count':len(findings),'findings':[fd(f) for f in findings],'detailed_reports':reports,'next_step':'Review, reproduce, and manually verify before submission.'})
@app.post('/api/generate-human-review-report')
def generate_human_review_report():d=request.get_json(silent=True) or {};return jsonify({'status':'report_ready_for_human_review','report':build_report(d.get('findings',[]),d.get('opportunity',{}))})
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.environ.get('PORT',8080)),debug=False)
