"""Authorized public bounty discovery, opportunity scoring, persistence and review workflow."""
from __future__ import annotations
import html, json, re, sqlite3, urllib.parse, urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

DB_PATH = "bughunter.db"
USER_AGENT = "Web3-BugHunter/1.0 (authorized-security-research; public-program-discovery)"

@dataclass
class Opportunity:
    id: str; source: str; name: str; url: str; status: str; max_bounty_usd: float
    scope_size: int; source_code_available: bool; competition_risk: float; difficulty: float
    estimated_hours: float; severity_potential: float; likelihood: float; attack_surface: List[str]
    scope_notes: str = ""; discovered_at: str = ""; score: float = 0.0
    metadata: Dict[str, Any] = None
    def to_dict(self):
        d=asdict(self); d["metadata"]=d.get("metadata") or {}; return d

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
            db.execute("CREATE TABLE IF NOT EXISTS opportunities (id TEXT PRIMARY KEY, source TEXT, name TEXT, url TEXT, status TEXT, max_bounty_usd REAL, scope_size INTEGER, source_code_available INTEGER, competition_risk REAL, difficulty REAL, estimated_hours REAL, severity_potential REAL, likelihood REAL, attack_surface TEXT, scope_notes TEXT, discovered_at TEXT, score REAL, metadata TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS hunts (id TEXT PRIMARY KEY, opportunity_id TEXT, status TEXT, finding_count INTEGER, notes TEXT, updated_at TEXT)")
    def upsert(self,o):
        with self._connect() as db:
            db.execute("INSERT INTO opportunities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET source=excluded.source,name=excluded.name,url=excluded.url,status=excluded.status,max_bounty_usd=excluded.max_bounty_usd,scope_size=excluded.scope_size,source_code_available=excluded.source_code_available,competition_risk=excluded.competition_risk,difficulty=excluded.difficulty,estimated_hours=excluded.estimated_hours,severity_potential=excluded.severity_potential,likelihood=excluded.likelihood,attack_surface=excluded.attack_surface,scope_notes=excluded.scope_notes,discovered_at=excluded.discovered_at,score=excluded.score,metadata=excluded.metadata",(o.id,o.source,o.name,o.url,o.status,o.max_bounty_usd,o.scope_size,int(o.source_code_available),o.competition_risk,o.difficulty,o.estimated_hours,o.severity_potential,o.likelihood,json.dumps(o.attack_surface),o.scope_notes,o.discovered_at,o.score,json.dumps(o.metadata or {})))
    def list(self,limit=50):
        with self._connect() as db: rows=db.execute("SELECT * FROM opportunities ORDER BY score DESC LIMIT ?",(limit,)).fetchall()
        cols=['id','source','name','url','status','max_bounty_usd','scope_size','source_code_available','competition_risk','difficulty','estimated_hours','severity_potential','likelihood','attack_surface','scope_notes','discovered_at','score','metadata']; out=[]
        for r in rows:
            d=dict(zip(cols,r)); d['source_code_available']=bool(d['source_code_available']); d['attack_surface']=json.loads(d['attack_surface'] or '[]'); d['metadata']=json.loads(d['metadata'] or '{}'); out.append(d)
        return out
    def set_hunt_status(self,opportunity_id,status,notes='',finding_count=0):
        with self._connect() as db: db.execute("INSERT INTO hunts VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,finding_count=excluded.finding_count,notes=excluded.notes,updated_at=excluded.updated_at",(f'{opportunity_id}:current',opportunity_id,status,finding_count,notes,_now()))
    def history(self,limit=100):
        with self._connect() as db: rows=db.execute("SELECT * FROM hunts ORDER BY updated_at DESC LIMIT ?",(limit,)).fetchall()
        return [dict(zip(['id','opportunity_id','status','finding_count','notes','updated_at'],r)) for r in rows]

class PublicProgramDiscovery:
    """Discover actual public program entries using ordinary HTTPS page access only."""
    SOURCES={'immunefi':'https://immunefi.com/bug-bounty/','hackerone':'https://www.hackerone.com/bug-bounty-programs','code4rena':'https://code4rena.com/contests','sherlock':'https://audits.sherlock.xyz/contests'}
    WEB3_TERMS=re.compile(r'web3|crypto|blockchain|defi|dao|dex|wallet|token|ethereum|solidity|smart contract|protocol|stablecoin|nft|layer[- ]?2',re.I)
    BOUNTY=re.compile(r'(?:up to|maximum|max\.?|bounty(?:\s+of)?|reward(?:\s+of)?|prize(?:\s+pool)?(?:\s+of)?)\s*[:\-]?\s*(?:\$|USD\s*)?([\d,]+(?:\.\d+)?)\s*([km])?',re.I)
    LINK=re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',re.I|re.S)
    def fetch(self,url,timeout=15):
        req=urllib.request.Request(url,headers={'User-Agent':USER_AGENT,'Accept':'text/html,application/xhtml+xml,application/json'})
        with urllib.request.urlopen(req,timeout=timeout) as r: return r.geturl(),r.read().decode('utf-8','replace')
    def _clean(self,s): return re.sub(r'\s+',' ',html.unescape(re.sub(r'<[^>]+>',' ',s))).strip()
    def _reward(self,text):
        vals=[]
        for m in self.BOUNTY.finditer(text):
            n=_num(m.group(1)); n*=1000 if (m.group(2) or '').lower()=='k' else 1_000_000 if (m.group(2) or '').lower()=='m' else 1
            if n>0: vals.append(n)
        return max(vals,default=0.0)
    def _candidate_links(self,base,body):
        seen=set(); out=[]
        for href,label in self.LINK.findall(body):
            label=self._clean(label); href=urllib.parse.urljoin(base,html.unescape(href)); host=urllib.parse.urlparse(href).netloc
            if href in seen or not label or href.startswith(('javascript:','mailto:')): continue
            if host and host != urllib.parse.urlparse(base).netloc: continue
            seen.add(href); out.append((href,label))
        return out
    def discover_platform(self,source,url,max_entries=100):
        try: final,body=self.fetch(url)
        except Exception as exc: return [],{'source':source,'url':url,'reachable':False,'error':str(exc)}
        results=[]
        for href,label in self._candidate_links(final,body):
            if not (self.WEB3_TERMS.search(label) or source in ('immunefi','code4rena','sherlock')): continue
            slug=re.sub(r'[^a-z0-9]+','-',label.lower()).strip('-')[:80]
            if not slug: continue
            contest=source in ('code4rena','sherlock') or 'contest' in href.lower()
            o=Opportunity(f'{source}:{slug}',source,label,href,'active',self._reward(label),1,True,.65,.65 if contest else .55,12,.75,.55 if contest else .45,['smart contracts','business logic','economic/state-machine analysis'],'Discovered from a public platform listing. Human must open the linked program/contest and verify exact in-scope assets, exclusions, dates, testing rules and submission requirements before any testing.',_now(),metadata={'platform_index':final,'public_listing':True,'discovery_method':'public_html_link_extraction'})
            o.score=score_opportunity(o); results.append(o)
            if len(results)>=max_entries: break
        if not results:
            o=Opportunity(f'feed:{source}',source,f'{source.title()} public program index',final,'feed_only',self._reward(self._clean(body)),0,True,.8,.8,2,.5,.2,['program discovery'],'Public index reachable, but no individual target was extracted. This record is not an authorization to test anything.',_now(),metadata={'platform_index':final,'public_listing':True,'discovery_method':'public_html_scan'}); o.score=score_opportunity(o); results=[o]
        return results,{'source':source,'url':final,'reachable':True,'bytes':len(body),'entries':len(results)}
    def discover_public_indexes(self,sources:Optional[Iterable[str]]=None):
        out=[]; diagnostics=[]
        for source in list(sources or self.SOURCES):
            if source not in self.SOURCES: continue
            found,diag=self.discover_platform(source,self.SOURCES[source]); out.extend(found); diagnostics.append(diag)
        return out,diagnostics
    def discover_from_json(self,payload:Iterable[Dict[str,Any]],source='manual-import'):
        out=[]
        for i,item in enumerate(payload or []):
            if not item.get('name') or not item.get('url'): continue
            o=Opportunity(str(item.get('id') or f"{source}:{i}:{item['name'].lower().replace(' ','-')}"),source,str(item['name']),str(item['url']),str(item.get('status','active')),_num(item.get('max_bounty_usd')),int(_num(item.get('scope_size'),1)),bool(item.get('source_code_available',True)),float(item.get('competition_risk',.5)),float(item.get('difficulty',.5)),float(item.get('estimated_hours',12)),float(item.get('severity_potential',.6)),float(item.get('likelihood',.4)),list(item.get('attack_surface',['smart contracts','business logic'])),str(item.get('scope_notes','')),_now(),metadata=item.get('metadata',{})); o.score=score_opportunity(o); out.append(o)
        return out

def build_report(findings,opportunity):
    return {'review_status':'UNVERIFIED — HUMAN REVIEW REQUIRED','do_not_auto_submit':True,'opportunity':{k:opportunity.get(k) for k in ('name','source','url','scope_notes','max_bounty_usd','score')},'findings':findings,'submission_checklist':['Confirm target is explicitly in scope and testing is permitted.','Reproduce independently in an authorized environment.','Confirm severity and economic impact.','Check known issues and duplicates.','Edit to include only verified evidence.','Submit manually only after human approval.']}
