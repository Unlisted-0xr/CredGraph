from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum

class SourceKind(StrEnum):
    LOCAL_FILE = "local_file"
    GIT_DIFF = "git_diff"
    GIT_FILE = "git_file"
    PACKAGE = "package"
    OTHER = "other"

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

@dataclass(frozen=True, slots=True)
class Observation:
    source_kind: SourceKind
    source_uri: str
    observed_at: str
    content: str
    locator: str = ""
    commit_id: str | None = None
    author: str | None = None
    repository: str | None = None
    path: str | None = None
    change: str | None = None
