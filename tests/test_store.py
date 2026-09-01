from credgraph.models import Observation, SourceKind
from credgraph.store import EvidenceStore

def test_fingerprint_correlation(tmp_path):
    db=EvidenceStore(tmp_path/"x.db")
    a=Observation(SourceKind.LOCAL_FILE,"repo-a/config", "2026-01-01T00:00:00+00:00",'TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"',"",repository="repo-a",path="config")
    b=Observation(SourceKind.GIT_DIFF,"repo-b#commit/2", "2026-02-01T00:00:00+00:00",'TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"',"2",author="dev",repository="repo-b",path="config",change="diff")
    assert db.add_observation(a)==1
    assert db.add_observation(b)==1
    clusters=db.clusters()
    assert len(clusters)==1 and clusters[0]["observations"]==2 and clusters[0]["repositories"]==2
    db.close()
