from credgraph.models import Observation, SourceKind
from credgraph.store import EvidenceStore
from credgraph.report import write_html, write_json

def test_reports(tmp_path):
    db=EvidenceStore(tmp_path/"x.db")
    db.add_observation(Observation(SourceKind.LOCAL_FILE,"x","2026-01-01T00:00:00+00:00",'TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"'))
    out=tmp_path/"report.html"; data=write_html(db,out)
    assert out.exists() and data["stats"]["findings"]==1
    outj=tmp_path/"report.json"; write_json(db,outj); assert outj.exists()
    db.close()
