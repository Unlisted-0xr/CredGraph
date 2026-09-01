from __future__ import annotations
import subprocess
from pathlib import Path
from .models import Observation, SourceKind, utc_now

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", "dist", "build"}

def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git","-C",str(root),*args], text=True, stderr=subprocess.DEVNULL)

def scan_path(path: str | Path, repository: str | None = None, history: bool = True, max_commits: int = 500) -> list[Observation]:
    root = Path(path).resolve()
    if root.is_file():
        return [Observation(SourceKind.LOCAL_FILE, str(root), utc_now(),
                            root.read_text(errors="replace"), repository=repository, path=root.name)]
    if (root / ".git").exists():
        return _scan_git(root, repository or root.name, history, max_commits)
    return _scan_files(root, repository)

def _scan_files(root: Path, repository: str | None) -> list[Observation]:
    out=[]
    for f in root.rglob("*"):
        if not f.is_file() or any(p in SKIP_DIRS for p in f.parts): continue
        try: text=f.read_text(errors="replace")
        except OSError: continue
        if len(text) > 5_000_000: continue
        out.append(Observation(SourceKind.LOCAL_FILE,str(f),utc_now(),text,repository=repository,path=str(f.relative_to(root))))
    return out

def _scan_git(root: Path, repository: str, history: bool, max_commits: int) -> list[Observation]:
    out=[]
    # Current tree: catches currently exposed material.
    out.extend(_scan_files(root, repository))
    if not history: return out
    try:
        commits = _git(root, "log", "--all", f"-n{max_commits}", "--format=%H%x00%aI%x00%an").splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return out

    seen_commits=set()
    for line in commits:
        parts=line.split("\x00")
        if len(parts)<3: continue
        sha, date, author=parts[:3]
        if sha in seen_commits: continue
        seen_commits.add(sha)
        try:
            patch = _git(root, "diff-tree", "--root", "--no-commit-id", "--unified=0", "-r", "--format=", sha)
        except subprocess.CalledProcessError:
            continue
        # Only changed lines are needed for historical exposure evidence.
        changed=[]
        current_path=""
        for ln in patch.splitlines():
            if ln.startswith("+++ b/") or ln.startswith("--- a/"):
                if ln.startswith("+++ b/"): current_path=ln[6:]
            elif ln.startswith("+") and not ln.startswith("+++"):
                changed.append(f"{current_path}:+:{ln[1:]}")
            elif ln.startswith("-") and not ln.startswith("---"):
                changed.append(f"{current_path}:-:{ln[1:]}")
        if changed:
            content="\n".join(changed)
            out.append(Observation(SourceKind.GIT_DIFF, f"{root}#commit/{sha}", date, content,
                                   locator=sha, commit_id=sha, author=author, repository=repository,
                                   path=current_path, change="diff"))
    return out
