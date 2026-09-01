from __future__ import annotations
import html, json
from pathlib import Path
from .risk import score_cluster

def build_report(store):
    clusters=[]
    for c in store.clusters():
        rows=store.by_fingerprint(c["fingerprint"])
        conf=max(float(r["confidence"]) for r in rows)
        typ=(c["types"] or "unknown").split(",")[0]
        score,label=score_cluster(observations=c["observations"],repositories=c["repositories"],
                                  authors=c["authors"],confidence=conf,secret_type=typ,
                                  historical=c["observations"]>1)
        clusters.append({**c,"confidence":round(conf,2),"risk_score":score,"risk":label,"preview":rows[0]["preview"]})
    return {"stats":store.stats(),"clusters":clusters}

def write_json(store,path):
    data=build_report(store); Path(path).write_text(json.dumps(data,indent=2),encoding="utf-8"); return data

def write_html(store,path):
    data=build_report(store); s=data["stats"]
    rows=[]
    for c in data["clusters"]:
        rows.append(f"<tr><td><code>{html.escape(c['fingerprint'][:16])}…</code></td><td>{html.escape(c['types'] or 'unknown')}</td><td>{c['observations']}</td><td>{c['first_seen']}</td><td>{c['last_seen']}</td><td>{c['risk_score']} / {html.escape(c['risk'])}</td></tr>")
    doc=f"""<!doctype html><html><head><meta charset=utf-8><title>CredGraph Investigation</title>
<style>body{{font:15px system-ui;margin:40px;max-width:1200px}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}.card{{border:1px solid #ddd;border-radius:10px;padding:16px;min-width:140px}}table{{width:100%;border-collapse:collapse;margin-top:24px}}th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}code{{font-family:ui-monospace}}</style></head>
<body><h1>CredGraph Investigation</h1><div class=cards>
<div class=card><b>Findings</b><div>{s['findings']}</div></div><div class=card><b>Credentials</b><div>{s['credentials']}</div></div>
<div class=card><b>Repositories</b><div>{s['repositories']}</div></div><div class=card><b>Commits</b><div>{s['commits']}</div></div></div>
<table><thead><tr><th>Fingerprint</th><th>Type</th><th>Occurrences</th><th>First seen</th><th>Last seen</th><th>Risk</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=6>No findings</td></tr>'}</tbody></table><p>Secrets are not stored in plaintext by CredGraph.</p></body></html>"""
    Path(path).write_text(doc,encoding="utf-8"); return data
