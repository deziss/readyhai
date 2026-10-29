"""Safe collection of target files (stdlib only).

* symlinks are never followed (not directories, not files, not the walk itself), files are opened with
  O_NOFOLLOW and must be regular files (no FIFOs/devices that could hang or leak),
* size and count are capped,
* content is redacted BEFORE it is chunked, embedded, stored or sent anywhere.
"""

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List

from .safety import redact

SUPPORTED_EXTENSIONS = {
    ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java",
    ".json", ".yaml", ".yml", ".toml", ".md", ".sarif", ".html",
}
IGNORE_DIRS = {".git", "node_modules", "target", "dist", "build", ".venv", "venv", "vendor", ".next", ".cache", "__pycache__"}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 5000


@dataclass
class FileRecord:
    rel: str
    kind: str
    ext: str
    text: str


def classify(ext: str) -> str:
    if ext in (".json", ".yaml", ".yml", ".toml"):
        return "spec_or_config"
    if ext in (".md", ".sarif"):
        return "report_or_doc"
    return "code"


def _read_regular_nofollow(path: str, max_bytes: int):
    """Bytes of a regular, non-symlink file, or None."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None  # symlink (ELOOP), permission, vanished
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(max_bytes + 1)[:max_bytes]
    finally:
        os.close(fd)


def load_files(
    target_dir: str,
    max_files: int = MAX_FILES,
    max_bytes: int = MAX_FILE_BYTES,
    warn: Callable[[str], None] = print,
) -> List[FileRecord]:
    root = os.path.abspath(target_dir)
    if not os.path.lexists(root):
        raise FileNotFoundError(f"Target path does not exist: {root}")
    if os.path.islink(root):
        raise ValueError(f"Target {root} is a symlink; pass the real path (symlinks are never followed)")

    out: List[FileRecord] = []
    skipped_links = 0

    def add(abs_path: str, rel: str) -> None:
        ext = os.path.splitext(abs_path)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            return
        data = _read_regular_nofollow(abs_path, max_bytes)
        if data is None:
            return
        text = redact(data.decode("utf-8", errors="replace"))
        if text.strip():
            out.append(FileRecord(rel=rel, kind=classify(ext), ext=ext, text=text))

    if os.path.isfile(root):
        add(root, os.path.basename(root))
        return out

    for dirpath, dirs, files in os.walk(root, followlinks=False):
        keep = []
        for d in sorted(dirs):
            if d in IGNORE_DIRS:
                continue
            if os.path.islink(os.path.join(dirpath, d)):
                skipped_links += 1
                continue
            keep.append(d)
        dirs[:] = keep
        for f in sorted(files):
            if len(out) >= max_files:
                warn(f"Stopped at {max_files} files (raise MAX_FILES to index more).")
                return out
            p = os.path.join(dirpath, f)
            if os.path.islink(p):
                skipped_links += 1
                continue
            add(p, str(Path(p).relative_to(root)))
    if skipped_links:
        warn(f"Skipped {skipped_links} symlink(s): symlinks are never followed.")
    return out
