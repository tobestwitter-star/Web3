"""Database backends: SQLite for local/test use and Neon PostgreSQL in production."""
from __future__ import annotations
import json, os, sqlite3
from datetime import datetime, timezone

try:
    import psycopg
except ImportError:
    psycopg = None


def is_postgres() -> bool:
    return bool(os.environ.get("DATABASE_URL"))


def connect(path: str):
    if not is_postgres():
        return sqlite3.connect(path)
    if psycopg is None:
        raise RuntimeError("psycopg is required when DATABASE_URL is configured")
    return psycopg.connect(os.environ["DATABASE_URL"])


class PostgresOpportunityStore:
    def __init__(self, _path="bughunter.db"):
        self._init()

    def _init(self):
        with connect("") as db:
            db.execute("""CREATE TABLE IF NOT EXISTS opportunities (
                id TEXT PRIMARY KEY, source TEXT, name TEXT, url TEXT, status TEXT,
                max_bounty_usd DOUBLE PRECISION, scope_size INTEGER, source_code_available BOOLEAN,
                competition_risk DOUBLE PRECISION, difficulty DOUBLE PRECISION, estimated_hours DOUBLE PRECISION,
                severity_potential DOUBLE PRECISION, likelihood DOUBLE PRECISION, attack_surface TEXT,
                scope_notes TEXT, discovered_at TEXT, score DOUBLE PRECISION, metadata TEXT)""")
            db.execute("""CREATE TABLE IF NOT EXISTS hunts (
                id TEXT PRIMARY KEY, opportunity_id TEXT, status TEXT, finding_count INTEGER,
                notes TEXT, updated_at TEXT)""")

    def upsert(self, o):
        with connect("") as db:
            db.execute("""INSERT INTO opportunities
            (id,source,name,url,status,max_bounty_usd,scope_size,source_code_available,competition_risk,difficulty,estimated_hours,severity_potential,likelihood,attack_surface,scope_notes,discovered_at,score,metadata)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT(id) DO UPDATE SET source=EXCLUDED.source,name=EXCLUDED.name,url=EXCLUDED.url,status=EXCLUDED.status,max_bounty_usd=EXCLUDED.max_bounty_usd,scope_size=EXCLUDED.scope_size,source_code_available=EXCLUDED.source_code_available,competition_risk=EXCLUDED.competition_risk,difficulty=EXCLUDED.difficulty,estimated_hours=EXCLUDED.estimated_hours,severity_potential=EXCLUDED.severity_potential,likelihood=EXCLUDED.likelihood,attack_surface=EXCLUDED.attack_surface,scope_notes=EXCLUDED.scope_notes,discovered_at=EXCLUDED.discovered_at,score=EXCLUDED.score,metadata=EXCLUDED.metadata""",
            (o.id,o.source,o.name,o.url,o.status,o.max_bounty_usd,o.scope_size,bool(o.source_code_available),o.competition_risk,o.difficulty,o.estimated_hours,o.severity_potential,o.likelihood,json.dumps(o.attack_surface),o.scope_notes,o.discovered_at,o.score,json.dumps(o.metadata or {})))

    def list(self, limit=50):
        with connect("") as db:
            rows=db.execute("SELECT id,source,name,url,status,max_bounty_usd,scope_size,source_code_available,competition_risk,difficulty,estimated_hours,severity_potential,likelihood,attack_surface,scope_notes,discovered_at,score,metadata FROM opportunities ORDER BY score DESC LIMIT %s", (min(int(limit),200),)).fetchall()
        cols=['id','source','name','url','status','max_bounty_usd','scope_size','source_code_available','competition_risk','difficulty','estimated_hours','severity_potential','likelihood','attack_surface','scope_notes','discovered_at','score','metadata']
        out=[]
        for r in rows:
            d=dict(zip(cols,r));d['source_code_available']=bool(d['source_code_available']);d['attack_surface']=json.loads(d['attack_surface'] or '[]');d['metadata']=json.loads(d['metadata'] or '{}');out.append(d)
        return out

    def set_hunt_status(self,oid,status,notes='',finding_count=0):
        with connect("") as db:
            db.execute("""INSERT INTO hunts(id,opportunity_id,status,finding_count,notes,updated_at)
            VALUES(%s,%s,%s,%s,%s,%s)
            ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,finding_count=EXCLUDED.finding_count,notes=EXCLUDED.notes,updated_at=EXCLUDED.updated_at""",
            (f'{oid}:current',oid,status,finding_count,notes,datetime.now(timezone.utc).isoformat()))

    def history(self,limit=100):
        with connect("") as db:
            rows=db.execute("SELECT id,opportunity_id,status,finding_count,notes,updated_at FROM hunts ORDER BY updated_at DESC LIMIT %s",(min(int(limit),200),)).fetchall()
        return [dict(zip(['id','opportunity_id','status','finding_count','notes','updated_at'],r)) for r in rows]


class PostgresResearchQueue:
    STATUSES=('queued','researching','validated','report_ready','completed','paused','failed')
    def __init__(self,_path='bughunter.db'):
        self._init()

    def _init(self):
        with connect("") as db:
            db.execute("""CREATE TABLE IF NOT EXISTS research_queue (
              id BIGSERIAL PRIMARY KEY, opportunity_id TEXT UNIQUE, priority DOUBLE PRECISION,
              status TEXT, attempts INTEGER DEFAULT 0, finding_count INTEGER DEFAULT 0,
              metadata TEXT DEFAULT '{}', created_at TEXT, updated_at TEXT)""")
            db.execute("""CREATE TABLE IF NOT EXISTS research_performance (
              id BIGSERIAL PRIMARY KEY, opportunity_id TEXT, vulnerability_class TEXT, outcome TEXT,
              research_minutes DOUBLE PRECISION DEFAULT 0, duplicate BOOLEAN DEFAULT FALSE,
              false_positive BOOLEAN DEFAULT FALSE, bounty_usd DOUBLE PRECISION DEFAULT 0,
              tool TEXT DEFAULT '', created_at TEXT)""")

    def enqueue(self,opportunity_id,priority,metadata=None):
        now=datetime.now(timezone.utc).isoformat()
        with connect("") as db: db.execute("""INSERT INTO research_queue(opportunity_id,priority,status,metadata,created_at,updated_at) VALUES(%s,%s,'queued',%s,%s,%s)
        ON CONFLICT(opportunity_id) DO UPDATE SET priority=EXCLUDED.priority,metadata=EXCLUDED.metadata,updated_at=EXCLUDED.updated_at""",(opportunity_id,float(priority),json.dumps(metadata or {}),now,now))

    def fill(self,opportunities,limit=50):
        ranked=[]
        for o in opportunities: ranked.append((float(o.get('score',0))*self.learning_factor(o.get('attack_surface') or []),o))
        for priority,o in sorted(ranked,key=lambda x:x[0],reverse=True)[:max(0,min(int(limit),200))]:
            meta=dict(o);meta['learning_factor']=self.learning_factor(o.get('attack_surface') or []);self.enqueue(str(o['id']),round(priority,2),meta)

    def next(self):
        with connect("") as db:
            row=db.execute("SELECT id,opportunity_id,priority,status,attempts,finding_count,metadata,created_at,updated_at FROM research_queue WHERE status='queued' ORDER BY priority DESC,created_at ASC LIMIT 1").fetchone()
            if not row:return None
            db.execute("UPDATE research_queue SET status='researching',attempts=attempts+1,updated_at=%s WHERE id=%s",(datetime.now(timezone.utc).isoformat(),row[0]))
            row=db.execute("SELECT id,opportunity_id,priority,status,attempts,finding_count,metadata,created_at,updated_at FROM research_queue WHERE id=%s",(row[0],)).fetchone()
        return self._row(row)

    def update(self,opportunity_id,status,findings=0,metadata=None):
        if status not in self.STATUSES: raise ValueError('invalid queue status')
        with connect("") as db: db.execute("UPDATE research_queue SET status=%s,finding_count=%s,metadata=COALESCE(%s,metadata),updated_at=%s WHERE opportunity_id=%s",(status,int(findings),json.dumps(metadata) if metadata is not None else None,datetime.now(timezone.utc).isoformat(),opportunity_id))

    def list(self,limit=100):
        with connect("") as db: rows=db.execute("SELECT id,opportunity_id,priority,status,attempts,finding_count,metadata,created_at,updated_at FROM research_queue ORDER BY CASE status WHEN 'researching' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END,priority DESC LIMIT %s",(min(int(limit),200),)).fetchall()
        return [self._row(r) for r in rows]

    def record_performance(self,opportunity_id,vulnerability_class,outcome,research_minutes=0,duplicate=False,false_positive=False,bounty_usd=0,tool=''):
        with connect("") as db: db.execute("INSERT INTO research_performance(opportunity_id,vulnerability_class,outcome,research_minutes,duplicate,false_positive,bounty_usd,tool,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",(opportunity_id,vulnerability_class,outcome,float(research_minutes),bool(duplicate),bool(false_positive),float(bounty_usd),tool,datetime.now(timezone.utc).isoformat()))

    def performance(self):
        with connect("") as db: rows=db.execute("SELECT vulnerability_class,COUNT(*),SUM(CASE WHEN outcome IN ('verified','report_ready') THEN 1 ELSE 0 END),SUM(false_positive::int),SUM(duplicate::int),AVG(research_minutes),SUM(bounty_usd) FROM research_performance GROUP BY vulnerability_class ORDER BY SUM(bounty_usd) DESC").fetchall()
        return [{'vulnerability_class':r[0],'investigations':r[1],'successful':r[2],'false_positives':r[3],'duplicates':r[4],'avg_research_minutes':round(r[5] or 0,2),'bounty_usd':round(r[6] or 0,2)} for r in rows]

    def learning_factor(self,attack_surface):
        stats=self.performance();surfaces={str(x).lower() for x in attack_surface or []};f=1.0
        for s in stats:
            if s['vulnerability_class'].lower() in surfaces and s['investigations']:
                rate=s['successful']/s['investigations'];fp=s['false_positives']/s['investigations'];f += .25*rate-.15*fp
        return round(max(.5,min(1.5,f)),3)

    def _row(self,r): return {'id':r[0],'opportunity_id':r[1],'priority':r[2],'status':r[3],'attempts':r[4],'finding_count':r[5],'metadata':json.loads(r[6] or '{}'),'created_at':r[7],'updated_at':r[8]}
