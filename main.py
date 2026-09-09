import os
from flask import Flask, jsonify, request
from advanced_web3_analyzer import AdvancedWeb3Analyzer, generate_detailed_report
from bounty_engine import OpportunityStore, PublicProgramDiscovery, build_report

app=Flask(__name__); store=OpportunityStore(os.environ.get('BUGHUNTER_DB','bughunter.db')); discovery=PublicProgramDiscovery()

def fd(f): return {'id':f.id,'type':f.vulnerability_type,'severity':f.severity,'category':f.category,'location':f.location,'description':f.description,'poc':f.proof_of_concept,'impact':f.economic_impact,'confidence':f.confidence,'bounty_low':f.bounty_estimate_low,'bounty_high':f.bounty_estimate_high,'requires_verification':True,'status':'UNVERIFIED — HUMAN REVIEW REQUIRED'}

@app.get('/api/health')
def health(): return jsonify({'status':'Web3 BugHunter running','human_review_required':True,'auto_submission':False})

@app.get('/api/opportunities')
def opportunities(): return jsonify({'opportunities':store.list(min(int(request.args.get('limit',50)),200)),'workflow':'Discover → Evaluate → Rank → Select → Investigate → Validate → Generate Report → Human Review → Manual Submission'})

@app.post('/api/discover')
def discover():
    data=request.get_json(silent=True) or {}; records=data.get('programs'); found=discovery.discover_from_json(records,data.get('source','manual-import')) if records is not None else discovery.discover_public_indexes()
    for o in found: store.upsert(o)
    return jsonify({'status':'discovery_complete','count':len(found),'opportunities':store.list(100)})

@app.post('/api/opportunities/<opportunity_id>/select')
def select_opportunity(opportunity_id):
    match=next((o for o in store.list(200) if o['id']==opportunity_id),None)
    if not match: return jsonify({'error':'Opportunity not found'}),404
    store.set_hunt_status(opportunity_id,'Investigating','Selected by expected-value ranking.')
    return jsonify({'status':'selected','opportunity':match,'human_review_required':True})

@app.get('/api/hunting-history')
def hunting_history(): return jsonify({'history':store.history()})

@app.post('/api/hunting-history/<opportunity_id>')
def update_hunt(opportunity_id):
    data=request.get_json(silent=True) or {}; status=data.get('status','Needs Research'); allowed={'Investigating','Needs Research','Rejected','False Positive','Verified','Report Ready','Submitted','Duplicate'}
    if status not in allowed: return jsonify({'error':'Invalid hunt status'}),400
    store.set_hunt_status(opportunity_id,status,str(data.get('notes','')),int(data.get('finding_count',0))); return jsonify({'status':'updated','opportunity_id':opportunity_id,'hunt_status':status})

@app.post('/api/analyze-advanced')
def analyze_advanced():
    data=request.get_json(silent=True) or {}; code=data.get('code'); name=data.get('protocol_name')
    if not code or not name: return jsonify({'error':'Missing protocol_code or protocol_name'}),400
    findings=AdvancedWeb3Analyzer().analyze_protocol(code,name); reports=[]
    for f in findings: reports.append({'finding_id':f.id,'vulnerability':f.vulnerability_type,'severity':f.severity,'confidence':f.confidence,'estimated_bounty':{'low':f.bounty_estimate_low,'high':f.bounty_estimate_high},'detailed_report':generate_detailed_report(f),'requires_manual_verification':True,'status':'UNVERIFIED — HUMAN REVIEW REQUIRED','learning_value':f.learning_value})
    return jsonify({'status':'analysis_complete','protocol':name,'findings_count':len(findings),'findings':[fd(f) for f in findings],'detailed_reports':reports,'next_step':'Review, reproduce, and manually verify before submission.'})

@app.post('/api/generate-human-review-report')
def generate_human_review_report():
    data=request.get_json(silent=True) or {}; return jsonify({'status':'report_ready_for_human_review','report':build_report(data.get('findings',[]),data.get('opportunity',{}))})

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT',8080)),debug=False)
