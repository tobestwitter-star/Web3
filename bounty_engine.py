"""Opportunity discovery, scoring, persistence, and report workflow."""
from __future__ import annotations
import json, re, sqlite3, urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

DB_PATH = "bughunter.db"
USER_AGENT = "Web3-BugHunter/1.0 (security-research-tool)"

@dataclass
class Opportunity:
    id: str; source: str; name: str; url: str; status: str; max_bounty_usd: float
    scope_size: int; source_code_available: bool; competition_risk: float; difficulty: float
    estimated_hours: float; severity_potential: float; likelihood: float; attack_surface: List[str]
    scope_notes: str = ""; discovered_at: str = ""; score: float = 0.0
    def to_dict(self): return asdict(self)

def _now(): return datetime.now(timezone.utc).isoformat()
def _num(v, default=0.0):
    if v is None: return default
    if isinstance(v,(int,float)): return float(v)
    try: return float(re.sub(r"[^0-9.]", "", str(v)) or default)
    except ValueError: return default

def score_opportunity(o: Opportunity) -> float:
    bounty=min(o.max_bounty_usd/25000,1); efficiency=max(0,min(1,1-o.estimated_hours/80))
    code=1 if o.source_code_available else .35; scope=max(0,min(1,1-o.scope_size/10000))
    competition=1-max(0,min(1,o.competition_risk)); difficulty=1-max(0,min(1,o.difficulty))
    severity=max(0,min(1,o.severity_potential)); likelihood=max(0,min(1,o.likelihood))
    raw=.22*bounty+.16*efficiency+.12*code+.08*scope+.10*competition+.08*difficulty+.12*severity+.12*likelihood
    return round(raw*100,2)

class OpportunityStore:
    def __init__(self,path=DB_PATH): self.path=path; self._init()
    def _connect(self): return sqlite3.connect(self.path)
    def _init(self):
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS opportunities (id TEXT PRIMARY KEY, source TEXT, name TEXT, url TEXT, status TEXT, max_bounty_usd REAL, scope_size INTEGER, source_code_available INTEGER, competition_risk REAL, difficulty REAL, estimated_hours REAL, severity_potential REAL, likelihood REAL, attack_surface TEXT, scope_notes TEXT, discovered_at TEXT, score REAL)")
            db.execute("CREATE TABLE IF NOT EXISTS hunts (id TEXT PRIMARY KEY, opportunity_id TEXT, status TEXT, finding_count INTEGER, notes TEXT, updated_at TEXT)")
    def upsert(self,o):
        with self._connect() as db:
            db.execute("INSERT INTO opportunities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET source=excluded.source,name=excluded.name,url=excluded.url,status=excluded.status,max_bounty_usd=excluded.max_bounty_usd,scope_size=excluded.scope_size,source_code_available=excluded.source_code_available,competition_risk=excluded.competition_risk,difficulty=excluded.difficulty,estimated_hours=excluded.estimated_hours,severity_potential=excluded.severity_potential,likelihood=excluded.likelihood,attack_surface=excluded.attack_surface,scope_notes=excluded.scope_notes,discovered_at=excluded.discovered_at,score=excluded.score",(o.id,o.source,o.name,o.url,o.status,o.max_bounty_usd,o.scope_size,int(o.source_code_available),o.competition_risk,o.difficulty,o.estimated_hours,o.severity_potential,o.likelihood,json.dumps(o.attack_surface),o.scope_notes,o.discovered_at,o.score))
    def list(self,limit=50):
        with self._connect() as db: rows=db.execute("SELECT * FROM opportunities ORDER BY score DESC LIMIT ?",(limit,)).fetchall()
        cols=['id','source','name','url','status','max_bounty_usd','scope_size','source_code_available','competition_risk','difficulty','estimated_hours','severity_potential','likelihood','attack_surface','scope_notes','discovered_at','score']; out=[]
        for r in rows:
            d=dict(zip(cols,r)); d['source_code_available']=bool(d['source_code_available']); d['attack_surface']=json.loads(d['attack_surface'] or '[]'); out.append(d)
        return out
    def set_hunt_status(self,opportunity_id,status,notes='',finding_count=0):
        with self._connect() as db: db.execute("INSERT INTO hunts VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,finding_count=excluded.finding_count,notes=excluded.notes,updated_at=excluded.updated_at",(f'{opportunity_id}:{status}',opportunity_id,status,finding_count,notes,_now()))
    def history(self,limit=100):
        with self._connect() as db: rows=db.execute("SELECT * FROM hunts ORDER BY updated_at DESC LIMIT ?",(limit,)).fetchall()
        return [dict(zip(['id','opportunity_id','status','finding_count','notes','updated_at'],r)) for r in rows]

class PublicProgramDiscovery:
    SOURCES={'immunefi':'https://immunefi.com/bug-bounty/','code4rena':'https://code4rena.com/','sherlock':'https://audits.sherlock.xyz/contests'}
    def fetch(self,url,timeout=10):
        req=urllib.request.Request(url,headers={'User-Agent':USER_AGENT})
        with urllib.request.urlopen(req,timeout=timeout) as r: return r.read().decode('utf-8','replace')
    def discover_from_json(self,payload:Iterable[Dict[str,Any]],source='import'):
        out=[]
        for i,item in enumerate(payload):
            if not item.get('name') or not item.get('url'): continue
            o=Opportunity(str(item.get('id') or f"{source}:{i}:{item['name'].lower().replace(' ','-')}"),source,str(item['name']),str(item['url']),str(item.get('status','active')),_num(item.get('max_bounty_usd')),int(_num(item.get('scope_size'),1)),bool(item.get('source_code_available',True)),float(item.get('competition_risk',.5)),float(item.get('difficulty',.5)),float(item.get('estimated_hours',12)),float(item.get('severity_potential',.6)),float(item.get('likelihood',.4)),list(item.get('attack_surface',['smart contracts','business logic'])),str(item.get('scope_notes','')),_now()); o.score=score_opportunity(o); out.append(o)
        return out
    def discover_public_indexes(self):
        out=[]
        for source,url in self.SOURCES.items():
            try: html=self.fetch(url)
            except Exception: continue
            o=Opportunity(f'feed:{source}',source,f'{source.title()} public program feed',url,'active',0,1,True,.5,.5,1,.5,.5,['program discovery'],f'Public index reachable ({len(html)} bytes); individual programs require scope verification.',_now()); o.score=score_opportunity(o); out.append(o)
        return out

def build_report(findings,opportunity):
    return {'review_status':'UNVERIFIED — HUMAN REVIEW REQUIRED','do_not_auto_submit':True,'opportunity':{k:opportunity.get(k) for k in ('name','source','url','scope_notes','max_bounty_usd','score')},'findings':findings,'submission_checklist':['Confirm target is explicitly in scope and testing is permitted.','Reproduce independently in an authorized environment.','Confirm severity and economic impact.','Check known issues and duplicates.','Edit to include only verified evidence.','Submit manually only after human approval.']}
