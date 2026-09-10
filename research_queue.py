"""Persistent, bounded research queue for continuous authorized hunting."""
from __future__ import annotations
import json,sqlite3
from datetime import datetime,timezone
from typing import Any,Dict,List
STATUSES=('queued','researching','validated','report_ready','completed','paused','failed')
class ResearchQueue:
 def __init__(self,path='bughunter.db'):self.path=path;self._init()
 def _db(self):return sqlite3.connect(self.path)
 def _init(self):
  with self._db() as db:
   db.execute('CREATE TABLE IF NOT EXISTS research_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, opportunity_id TEXT UNIQUE, priority REAL, status TEXT, attempts INTEGER DEFAULT 0, finding_count INTEGER DEFAULT 0, metadata TEXT DEFAULT "{}", created_at TEXT, updated_at TEXT)')
   db.execute('CREATE TABLE IF NOT EXISTS research_performance (id INTEGER PRIMARY KEY AUTOINCREMENT, opportunity_id TEXT, vulnerability_class TEXT, outcome TEXT, research_minutes REAL DEFAULT 0, duplicate INTEGER DEFAULT 0, false_positive INTEGER DEFAULT 0, bounty_usd REAL DEFAULT 0, tool TEXT DEFAULT "", created_at TEXT)')
 def enqueue(self,opportunity_id,priority,metadata=None):
  now=datetime.now(timezone.utc).isoformat()
  with self._db() as db:db.execute('INSERT INTO research_queue(opportunity_id,priority,status,metadata,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(opportunity_id) DO UPDATE SET priority=excluded.priority,metadata=excluded.metadata,updated_at=excluded.updated_at',(opportunity_id,float(priority),'queued',json.dumps(metadata or {}),now,now))
 def fill(self,opportunities,limit=50):
  ranked=[]
  for o in opportunities:
   factor=self.learning_factor(o.get('attack_surface') or [])
   ranked.append((float(o.get('score',0))*factor,o))
  for priority,o in sorted(ranked,key=lambda x:x[0],reverse=True)[:max(0,min(int(limit),200))]:
   meta=dict(o);meta['learning_factor']=self.learning_factor(o.get('attack_surface') or []);self.enqueue(str(o['id']),round(priority,2),meta)
 def next(self):
  with self._db() as db:
   row=db.execute('SELECT * FROM research_queue WHERE status="queued" ORDER BY priority DESC,created_at ASC LIMIT 1').fetchone()
   if not row:return None
   db.execute('UPDATE research_queue SET status="researching",attempts=attempts+1,updated_at=? WHERE id=?',(datetime.now(timezone.utc).isoformat(),row[0]))
   updated=db.execute('SELECT * FROM research_queue WHERE id=?',(row[0],)).fetchone()
  return self._row(updated)
 def update(self,opportunity_id,status,findings=0,metadata=None):
  if status not in STATUSES:raise ValueError('invalid queue status')
  with self._db() as db:db.execute('UPDATE research_queue SET status=?,finding_count=?,metadata=COALESCE(?,metadata),updated_at=? WHERE opportunity_id=?',(status,int(findings),json.dumps(metadata) if metadata is not None else None,datetime.now(timezone.utc).isoformat(),opportunity_id))
 def list(self,limit=100):
  with self._db() as db:rows=db.execute('SELECT * FROM research_queue ORDER BY CASE status WHEN "researching" THEN 0 WHEN "queued" THEN 1 ELSE 2 END,priority DESC LIMIT ?',(min(int(limit),200),)).fetchall()
  return [self._row(r) for r in rows]
 def record_performance(self,opportunity_id,vulnerability_class,outcome,research_minutes=0,duplicate=False,false_positive=False,bounty_usd=0,tool=''):
  with self._db() as db:db.execute('INSERT INTO research_performance(opportunity_id,vulnerability_class,outcome,research_minutes,duplicate,false_positive,bounty_usd,tool,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(opportunity_id,vulnerability_class,outcome,float(research_minutes),int(duplicate),int(false_positive),float(bounty_usd),tool,datetime.now(timezone.utc).isoformat()))
 def performance(self):
  with self._db() as db:rows=db.execute('SELECT vulnerability_class,COUNT(*),SUM(CASE WHEN outcome IN ("verified","report_ready") THEN 1 ELSE 0 END),SUM(false_positive),SUM(duplicate),AVG(research_minutes),SUM(bounty_usd) FROM research_performance GROUP BY vulnerability_class ORDER BY SUM(bounty_usd) DESC').fetchall()
  return [{'vulnerability_class':r[0],'investigations':r[1],'successful':r[2],'false_positives':r[3],'duplicates':r[4],'avg_research_minutes':round(r[5] or 0,2),'bounty_usd':round(r[6] or 0,2)} for r in rows]
 def learning_factor(self,attack_surface):
  stats=self.performance();surfaces={str(x).lower() for x in attack_surface or []};f=1.0
  for s in stats:
   if s['vulnerability_class'].lower() in surfaces and s['investigations']:
    rate=s['successful']/s['investigations'];fp=s['false_positives']/s['investigations'];f += .25*rate-.15*fp
  return round(max(.5,min(1.5,f)),3)
 def _row(self,r):return {'id':r[0],'opportunity_id':r[1],'priority':r[2],'status':r[3],'attempts':r[4],'finding_count':r[5],'metadata':json.loads(r[6] or '{}'),'created_at':r[7],'updated_at':r[8]}
