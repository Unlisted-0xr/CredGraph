from __future__ import annotations
import sqlite3, secrets
from pathlib import Path
from .detect import detect
from .fingerprint import fingerprint_secret, redact_preview
from .models import Observation

SCHEMA="""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(
 id INTEGER PRIMARY KEY,
 detector TEXT NOT NULL, secret_type TEXT NOT NULL, fingerprint TEXT NOT NULL,
 preview TEXT NOT NULL, confidence REAL NOT NULL, source_kind TEXT NOT NULL,
 source_uri TEXT NOT NULL, locator TEXT NOT NULL, observed_at TEXT NOT NULL,
 commit_id TEXT, author TEXT, repository TEXT, path TEXT, change TEXT,
 line INTEGER, context TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_finding ON findings(fingerprint,source_uri,locator,detector,line);
CREATE INDEX IF NOT EXISTS idx_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_repo ON findings(repository);
CREATE INDEX IF NOT EXISTS idx_time ON findings(observed_at);
"""

class EvidenceStore:
    def __init__(self,path):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
        self.conn=sqlite3.connect(self.path); self.conn.row_factory=sqlite3.Row
        self.conn.executescript(SCHEMA)
        row=self.conn.execute("SELECT value FROM metadata WHERE key='fp_key'").fetchone()
        if row: self.fp_key=bytes.fromhex(row["value"])
        else:
            self.fp_key=secrets.token_bytes(32)
            self.conn.execute("INSERT INTO metadata VALUES('fp_key',?)",(self.fp_key.hex(),)); self.conn.commit()

    def add_observation(self,obs:Observation)->int:
        count=0
        for d in detect(obs.content):
            fp=fingerprint_secret(d.value,self.fp_key)
            preview=redact_preview(d.value)
            try:
                self.conn.execute("""INSERT INTO findings
                (detector,secret_type,fingerprint,preview,confidence,source_kind,source_uri,locator,observed_at,
                 commit_id,author,repository,path,change,line,context)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (d.detector,d.secret_type,fp,preview,d.confidence,obs.source_kind.value,obs.source_uri,
                 obs.locator,obs.observed_at,obs.commit_id,obs.author,obs.repository,obs.path,obs.change,d.line,d.context))
                count+=1
            except sqlite3.IntegrityError: pass
        self.conn.commit(); return count

    def all_findings(self): return self.conn.execute("SELECT * FROM findings ORDER BY observed_at DESC,id DESC").fetchall()
    def by_fingerprint(self,fp): return self.conn.execute("SELECT * FROM findings WHERE fingerprint=? ORDER BY observed_at,id",(fp,)).fetchall()
    def clusters(self):
        rows=self.conn.execute("""SELECT fingerprint,MIN(observed_at) first_seen,MAX(observed_at) last_seen,
        COUNT(*) observations,COUNT(DISTINCT repository) repositories,COUNT(DISTINCT author) authors,
        COUNT(DISTINCT source_kind) source_kinds,GROUP_CONCAT(DISTINCT secret_type) types
        FROM findings GROUP BY fingerprint ORDER BY last_seen DESC""").fetchall()
        return [dict(r) for r in rows]
    def stats(self):
        return dict(self.conn.execute("""SELECT COUNT(*) findings,
        COUNT(DISTINCT fingerprint) credentials,COUNT(DISTINCT repository) repositories,
        COUNT(DISTINCT commit_id) commits,COUNT(DISTINCT secret_type) secret_types FROM findings""").fetchone())
    def close(self): self.conn.close()
