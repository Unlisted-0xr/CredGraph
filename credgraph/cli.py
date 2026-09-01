from __future__ import annotations
import argparse, json
from pathlib import Path
from .collectors import scan_path
from .risk import score_cluster
from .store import EvidenceStore
from .report import write_html, write_json

def cmd_scan(a):
    st=EvidenceStore(a.db)
    obs=scan_path(a.path,repository=a.repository,history=not a.no_history,max_commits=a.max_commits)
    added=sum(st.add_observation(o) for o in obs)
    stats=st.stats()
    print(f"observations={len(obs)} new_findings={added} total_findings={stats['findings']} credentials={stats['credentials']} db={Path(a.db).resolve()}")
    st.close(); return 0

def cmd_findings(a):
    st=EvidenceStore(a.db); rows=st.all_findings()
    if a.json: print(json.dumps([dict(r) for r in rows],indent=2))
    else:
        if not rows: print("No findings."); st.close(); return 0
        for r in rows:
            print(f"[{float(r['confidence']):.2f}] {r['secret_type']:<22} {r['fingerprint'][:16]}… {r['source_kind']} {r['repository'] or '-'} {r['path'] or r['locator'] or '-'}:{r['line']}")
    st.close(); return 0

def cmd_clusters(a):
    st=EvidenceStore(a.db); out=[]
    for c in st.clusters():
        rows=st.by_fingerprint(c["fingerprint"]); conf=max(float(r["confidence"]) for r in rows)
        typ=(c["types"] or "unknown").split(",")[0]
        score,label=score_cluster(observations=c["observations"],repositories=c["repositories"],authors=c["authors"],
                                  confidence=conf,secret_type=typ,historical=c["observations"]>1)
        out.append({**c,"confidence":round(conf,2),"risk_score":score,"risk":label,"preview":rows[0]["preview"]})
    print(json.dumps(out,indent=2)); st.close(); return 0

def cmd_timeline(a):
    st=EvidenceStore(a.db); rows=st.by_fingerprint(a.fingerprint)
    if not rows: print("fingerprint not found"); st.close(); return 2
    for r in rows:
        print(f"{r['observed_at']} | {r['source_kind']} | {r['repository'] or '-'} | {r['author'] or '-'} | {r['path'] or r['locator'] or '-'} | {r['change'] or 'observed'}")
    st.close(); return 0

def cmd_report(a):
    st=EvidenceStore(a.db)
    if a.format=="json": write_json(st,a.output)
    else: write_html(st,a.output)
    print(f"report={Path(a.output).resolve()}"); st.close(); return 0

def cmd_stats(a):
    st=EvidenceStore(a.db); print(json.dumps(st.stats(),indent=2)); st.close(); return 0

def build_parser():
    p=argparse.ArgumentParser(prog="credgraph",description="Credential exposure investigation and correlation engine")
    s=p.add_subparsers(dest="command",required=True)
    x=s.add_parser("scan",help="scan an authorized file, directory, or Git repository")
    x.add_argument("path"); x.add_argument("--db",default="credgraph.db"); x.add_argument("--repository")
    x.add_argument("--no-history",action="store_true"); x.add_argument("--max-commits",type=int,default=500); x.set_defaults(func=cmd_scan)
    x=s.add_parser("findings",help="list findings"); x.add_argument("--db",default="credgraph.db"); x.add_argument("--json",action="store_true"); x.set_defaults(func=cmd_findings)
    x=s.add_parser("clusters",help="correlate repeated credential fingerprints"); x.add_argument("--db",default="credgraph.db"); x.set_defaults(func=cmd_clusters)
    x=s.add_parser("timeline",help="show evidence timeline for one fingerprint"); x.add_argument("--db",default="credgraph.db"); x.add_argument("--fingerprint",required=True); x.set_defaults(func=cmd_timeline)
    x=s.add_parser("report",help="generate an investigation report"); x.add_argument("--db",default="credgraph.db"); x.add_argument("--format",choices=("html","json"),default="html"); x.add_argument("--output",default="credgraph-report.html"); x.set_defaults(func=cmd_report)
    x=s.add_parser("stats",help="show database statistics"); x.add_argument("--db",default="credgraph.db"); x.set_defaults(func=cmd_stats)
    return p

def main():
    parser=build_parser()
    args=parser.parse_args()
    return args.func(args)
