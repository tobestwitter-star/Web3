"""Authorized public bounty discovery, opportunity scoring, persistence and review workflow."""
from __future__ import annotations
import html, json, re, sqlite3, urllib.parse, urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
DB_PATH="bughunter.db"; USER_AGENT="Web3-BugHunter/1.0 (authorized-security-research; public-program-discovery)"
@dataclass
class Opportunity:
    id:str; source:str; name:str; url:str; status:str; max_bounty_usd:float; scope_size:int; source_code_available:bool; competition_risk:float; difficulty:float; estimated_hours:float; severity_potential:float; likelihood:float; attack_surface:List[str]; scope_notes:str=""; discovered_at:str=""; score:float=0.0; metadata:Dict[str,Any]=None
    def to_dict(self): d=asdict(self); d['metadata']=d.get('metadata') or {}; return d
def _now(): return datetime.now(timezone.utc).isoformat()
def _num(v,default=0.0):
    if v is None:return default
    if isinstance(v,(int,float)):return float(v)
    try:return float(re.sub(r'[^0-9.]','',str(v)) or default)
    except ValueError:return default
def score_opportunity(o):
    bounty=min(o.max_bounty_usd/25000,1); efficiency=max(0,min(1,1-o.estimated_hours/80)); code=1 if o.source_code_available else .35; scope=max(0,min(1,1-o.scope_size/10000)); competition=1-max(0,min(1,o.competition_risk)); difficulty=1-max(0,min(1,o.difficulty)); severity=max(0,min(1,o.severity_potential)); likelihood=max(0,min(1,o.likelihood)); return round((.22*bounty+.16*efficiency+.12*code+.08*scope+.10*competition+.08*difficulty+.12*severity+.12*likelihood)*100,2)
class OpportunityStore:
    def __init__(self,path=DB_PATH):self.path=path;self._init()
    def _connect(self):return sqlite3.connect(self.path)
    def _init(self):
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS opportunities (id TEXT PRIMARY KEY, source TEXT, name TEXT, url TEXT, status TEXT, max_bounty_usd REAL, scope_size INTEGER, source_code_available INTEGER, competition_risk REAL, difficulty REAL, estimated_hours REAL, severity_potential REAL, likelihood REAL, attack_surface TEXT, scope_notes TEXT, discovered_at TEXT, score REAL, metadata TEXT)"); cols={r[1] for r in db.execute('PRAGMA table_info(opportunities)')};
            if 'metadata' not in cols:db.execute("ALTER TABLE opportunities ADD COLUMN metadata TEXT DEFAULT '{}'")
            db.execute("CREATE TABLE IF NOT EXISTS hunts (id TEXT PRIMARY KEY, opportunity_id TEXT, status TEXT, finding_count INTEGER, notes TEXT, updated_at TEXT)")
    def upsert(self,o):
        with self._connect() as db:db.execute("INSERT INTO opportunities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET source=excluded.source,name=excluded.name,url=excluded.url,status=excluded.status,max_bounty_usd=excluded.max_bounty_usd,scope_size=excluded.scope_size,source_code_available=excluded.source_code_available,competition_risk=excluded.competition_risk,difficulty=excluded.difficulty,estimated_hours=excluded.estimated_hours,severity_potential=excluded.severity_potential,likelihood=excluded.likelihood,attack_surface=excluded.attack_surface,scope_notes=excluded.scope_notes,discovered_at=excluded.discovered_at,score=excluded.score,metadata=excluded.metadata",(o.id,o.source,o.name,o.url,o.status,o.max_bounty_usd,o.scope_size,int(o.source_code_available),o.competition_risk,o.difficulty,o.estimated_hours,o.severity_potential,o.likelihood,json.dumps(o.attack_surface),o.scope_notes,o.discovered_at,o.score,json.dumps(o.metadata or {})))
    def list(self,limit=50):
        with self._connect() as db:rows=db.execute('SELECT * FROM opportunities ORDER BY score DESC LIMIT ?',(limit,)).fetchall()
        cols=['id','source','name','url','status','max_bounty_usd','scope_size','source_code_available','competition_risk','difficulty','estimated_hours','severity_potential','likelihood','attack_surface','scope_notes','discovered_at','score','metadata'];out=[]
        for r in rows:
            d=dict(zip(cols,r));d['source_code_available']=bool(d['source_code_available']);d['attack_surface']=json.loads(d['attack_surface'] or '[]');d['metadata']=json.loads(d['metadata'] or '{}');out.append(d)
        return out
    def set_hunt_status(self,oid,status,notes='',finding_count=0):
        with self._connect() as db:db.execute("INSERT INTO hunts VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,finding_count=excluded.finding_count,notes=excluded.notes,updated_at=excluded.updated_at",(f'{oid}:current',oid,status,finding_count,notes,_now()))
    def history(self,limit=100):
        with self._connect() as db:rows=db.execute('SELECT * FROM hunts ORDER BY updated_at DESC LIMIT ?',(limit,)).fetchall()
        return [dict(zip(['id','opportunity_id','status','finding_count','notes','updated_at'],r)) for r in rows]
class PublicProgramDiscovery:
    SOURCES={'immunefi_api':'https://immunefi.com/public-api/bounties.json','immunefi_snapshots':'https://raw.githubusercontent.com/pratraut/Immunefi-Bug-Bounty-Programs-Snapshots/main/projects.json','hackerone':'https://www.hackerone.com/bug-bounty-programs','code4rena':'https://code4rena.com/contests','sherlock':'https://audits.sherlock.xyz/contests','codehawks':'https://codehawks.cyfrin.io/contests','cantina':'https://cantina.xyz/opportunities/competitions'}
    WEB3_TERMS=re.compile(r'web3|crypto|blockchain|defi|dao|dex|wallet|token|ethereum|solidity|smart contract|protocol|stablecoin|nft|layer[- ]?2',re.I); BOUNTY=re.compile(r'(?:up to|maximum|max\.?|bounty(?:\s+of)?|reward(?:\s+of)?|prize(?:\s+pool)?(?:\s+of)?)\s*[:\-]?\s*(?:\$|USD\s*)?([\d,]+(?:\.\d+)?)\s*([km])?',re.I); LINK=re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',re.I|re.S)
    def fetch(self,url,timeout=15):
        req=urllib.request.Request(url,headers={'User-Agent':USER_AGENT,'Accept':'text/html,application/xhtml+xml,application/json'}); 
        with urllib.request.urlopen(req,timeout=timeout) as r:return r.geturl(),r.read().decode('utf-8','replace')
    def _clean(self,s):return re.sub(r'\s+',' ',html.unescape(re.sub(r'<[^>]+>',' ',s))).strip()
    def _reward(self,text):
        vals=[]
        for m in self.BOUNTY.finditer(text):
            n=_num(m.group(1));n*=1000 if (m.group(2) or '').lower()=='k' else 1000000 if (m.group(2) or '').lower()=='m' else 1;vals.append(n)
        return max(vals,default=0.0)
    def _make(self,source,name,url,status='active',bounty=0,scope=1,code=True,notes='',metadata=None,difficulty=.55,likelihood=.45):
        o=Opportunity(f'{source}:{re.sub(r"[^a-z0-9]+","-",name.lower()).strip("-")[:90]}',source,name,url,status,bounty,scope,code,.65,difficulty,12,.75,likelihood,['smart contracts','business logic','economic/state-machine analysis'],notes,_now(),metadata=metadata or {});o.score=score_opportunity(o);return o
    def _immunefi_json(self,payload,source='immunefi_api'):
        if isinstance(payload,dict):payload=payload.get('bounties') or payload.get('data') or payload.get('programs') or []
        out=[]
        for item in payload or []:
            if not isinstance(item,dict) or not item.get('project'):continue
            slug=item.get('slug','');assets=item.get('assets') or item.get('assetsInScope') or [];rewards=item.get('rewards') or [];maxb=_num(item.get('maxBounty') or item.get('max_bounty_usd'))
            if not maxb and isinstance(rewards,list):maxb=max((_num(x.get('max')) if isinstance(x,dict) else _num(x) for x in rewards),default=0)
            end=item.get('endDate') or item.get('end_date');status='active' if not end or str(end)>=datetime.now(timezone.utc).date().isoformat() else 'ended';url=f'https://immunefi.com/bug-bounty/{slug}/information/' if slug else 'https://immunefi.com/bug-bounty/'
            out.append(self._make(source,str(item['project']),url,status,maxb,len(assets) or 1,True,'Public Immunefi catalog record. Human must verify current scope, exclusions, testing/safe-harbor rules and submission requirements.',{'slug':slug,'assets':assets,'rewards':rewards,'ecosystems':item.get('ecosystem') or item.get('ecosystems') or [],'languages':item.get('language') or item.get('languages') or [],'program_type':item.get('programType'),'project_type':item.get('projectType'),'launch_date':item.get('launchDate') or item.get('launch_date'),'end_date':end,'rules':item.get('rules'),'out_of_scope':item.get('outOfScopeImpacts') or item.get('out_of_scope')},.45,.60 if assets else .42))
        return out
    def _candidate_links(self,base,body):
        seen=set();out=[]
        for href,label in self.LINK.findall(body):
            label=self._clean(label);href=urllib.parse.urljoin(base,html.unescape(href));host=urllib.parse.urlparse(href).netloc
            if href in seen or not label or href.startswith(('javascript:','mailto:')) or (host and host!=urllib.parse.urlparse(base).netloc):continue
            seen.add(href);out.append((href,label))
        return out
    def discover_platform(self,source,url,max_entries=100):
        if source in ('immunefi_api','immunefi_snapshots'):
            try:_,body=self.fetch(url);return self._immunefi_json(json.loads(body),source),{'source':source,'url':url,'reachable':True,'entries':'json'}
            except Exception as exc:return [],{'source':source,'url':url,'reachable':False,'error':str(exc)}
        try:final,body=self.fetch(url)
        except Exception as exc:return [],{'source':source,'url':url,'reachable':False,'error':str(exc)}
        results=[]
        for href,label in self._candidate_links(final,body):
            if not (self.WEB3_TERMS.search(label) or source in ('code4rena','sherlock','codehawks','cantina')):continue
            contest=source in ('code4rena','sherlock','codehawks','cantina') or 'contest' in href.lower();o=self._make(source,label,href,'active',self._reward(label),1,True,'Public listing; human must verify exact scope, exclusions, dates and testing rules before testing.',{'platform_index':final,'public_listing':True,'discovery_method':'public_html_link_extraction'},.65 if contest else .55,.55 if contest else .45);results.append(o)
            if len(results)>=max_entries:break
        if not results:results=[self._make(f'feed:{source}',f'{source.title()} public program index',final,'feed_only',self._reward(self._clean(body)),0,True,'Index reachable but no actionable individual target extracted; not authorization.',{'platform_index':final},.8,.2)]
        return results,{'source':source,'url':final,'reachable':True,'bytes':len(body),'entries':len(results)}
    def discover_public_indexes(self,sources:Optional[Iterable[str]]=None):
        out=[];diagnostics=[]
        for source in list(sources or self.SOURCES):
            if source not in self.SOURCES:continue
            found,diag=self.discover_platform(source,self.SOURCES[source]);out.extend(found);diagnostics.append(diag)
        return out,diagnostics
    def discover_from_json(self,payload,source='manual-import'):
        if source.startswith('immunefi'):return self._immunefi_json(payload,source)
        return [self._make(source,str(i['name']),str(i['url']),str(i.get('status','active')),_num(i.get('max_bounty_usd')),int(_num(i.get('scope_size'),1)),bool(i.get('source_code_available',True)),str(i.get('scope_notes','')),i.get('metadata',{}),float(i.get('difficulty',.5)),float(i.get('likelihood',.4))) for i in (payload or []) if i.get('name') and i.get('url')]
def build_report(findings,opportunity):
    opp=opportunity or {};scope_evidence=opp.get('scope_evidence') or opp.get('scope_notes') or opp.get('metadata',{}).get('rules') or 'Public program listing; exact scope and authorization require human verification.'
    normalized=[]
    for f in findings or []:
        desc=f.get('description') or f.get('hypothesis','')
        normalized.append({'title':f.get('title') or f.get('vulnerability') or 'Potential vulnerability','severity':f.get('severity') or f.get('severity_potential') or 'unrated','affected_contracts':f.get('contracts') or ([f.get('contract')] if f.get('contract') else ([opp.get('name')] if opp.get('name') else [])),'affected_functions':f.get('functions') or ([f.get('function')] if f.get('function') else []),'root_cause':f.get('root_cause') or desc,'attack_scenario':f.get('attack_scenario') or f.get('hypothesis') or desc,'prerequisites':f.get('prerequisites') or [],'poc_reproduction':f.get('poc') or f.get('execution_evidence') or f.get('proof_of_concept') or 'Local reproduction required before submission.','evidence':f.get('evidence') or f.get('execution_evidence') or [],'impact':f.get('impact') or f.get('economic_impact') or 'Impact requires human verification.','economic_impact':f.get('economic_analysis') or f.get('economic_impact') or {},'confidence':f.get('confidence',f.get('cross_tool_confidence',0.0)),'remediation':f.get('remediation') or 'Apply the minimal state/authorization/invariant fix and add a regression test.','scope_evidence':scope_evidence,'possible_duplicate_indicators':f.get('possible_duplicate_indicators') or f.get('duplicate_indicators') or [],'status':'UNVERIFIED — HUMAN REVIEW REQUIRED'})
    return {'review_status':'UNVERIFIED — HUMAN REVIEW REQUIRED','do_not_auto_submit':True,'opportunity':{k:opp.get(k) for k in ('name','source','url','scope_notes','max_bounty_usd','score')},'scope_evidence':scope_evidence,'findings':normalized,'submission_checklist':['Confirm target is explicitly in scope and testing is permitted.','Reproduce independently in an authorized environment.','Confirm severity and economic impact.','Check known issues and duplicates.','Edit to include only verified evidence.','Submit manually only after human approval.']}
