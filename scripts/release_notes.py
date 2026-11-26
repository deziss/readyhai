#!/usr/bin/env python3
"""GitHub Release title + description for a tag, built from CHANGELOG.md.

Usage:
    scripts/release_notes.py <version>                 # notes -> stdout
    scripts/release_notes.py <version> OUT.md          # notes -> file
    scripts/release_notes.py --title <version>         # release title -> stdout

The description always leads with a highlighted-point summary: the bold
lead-ins of the version's Added/Changed/Fixed bullets, distilled into
one-line highlights, followed by the full changelog section.

A tag whose CHANGELOG.md has no `## [x.y.z]` section fails (exit 1) -
every release must ship a real title and description, never an empty one.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
MAX_HIGHLIGHTS = 8
# a bullet with a bold lead-in, e.g. "- **Engine (`src/exploits/`)**: safe ..."
LEAD_BOLD = re.compile(r"^\s*-\s+\*\*([^*]{3,90})\*\*\s*[:\u2014\u2013-]?\s*(.*)$")


def _balanced_prefix(text: str, idx: int) -> bool:
    """True when brackets/parens/backticks are balanced in text[:idx]."""
    head = text[:idx]
    for opener, closer in (("[", "]"), ("(", ")")):
        if head.count(opener) != head.count(closer):
            return False
    return head.count("`") % 2 == 0


def _defining_clause(tail: str) -> str:
    """First self-contained clause of a bullet: drop code-path prefixes and
    cut at the first sentence-ish delimiter that is not inside [] () or ``."""
    tail = re.sub(r"^\([^)]*\)\s*:?\s*", "", tail)
    best = len(tail)
    for sep in (" — ", ". ", "; ", "; ", " ("):
        start = 1 if sep == " (" else 40  # a paren cut only after some prose
        i = tail.find(sep, start)
        while i != -1 and not _balanced_prefix(tail, i):
            i = tail.find(sep, i + 1)
        if 40 < i < best:
            best = i
    clause = tail[:best] if best < len(tail) else tail
    if len(clause) > 110:
        clause = clause[:107].rstrip() + "…"
    return clause.rstrip(" .,;:").strip()


def section(version: str) -> str:
    head, out, inside = f"## [{version}]", [], False
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        if line.rstrip().startswith(head):
            inside = True
            continue
        if inside:
            if line.startswith("## ["):
                break
            out.append(line)
    text = "\n".join(out).strip()
    if not text:
        sys.exit(f"release_notes: CHANGELOG.md has no '## [{version}]' section; "
                 "every release must document what shipped")
    return text


def highlights(sec: str) -> list[str]:
    """Bold lead-ins from Added/Changed/Fixed bullets, first clause, deduped."""
    want, keep = [], {"Added", "Changed", "Fixed", "Security", "Removed"}
    bucket = None
    for line in sec.splitlines():
        m = re.match(r"^###\s+(.*)$", line)
        if m:
            bucket = m.group(1).strip()
            continue
        if bucket not in keep:
            continue
        m = LEAD_BOLD.match(line)
        if not m:
            continue
        t = m.group(1).strip().rstrip(":：")
        first = _defining_clause(m.group(2).strip())
        point = f"**{t}**" + (f" — {first}." if first else "")
        if point not in want:
            want.append(point)
    return want[:MAX_HIGHLIGHTS]


def previous_tag(version: str) -> str | None:
    try:
        tags = subprocess.run(["git", "tag", "--sort=-v:refname"], cwd=ROOT,
                              capture_output=True, text=True, check=True).stdout.split()
    except subprocess.CalledProcessError:
        return None
    for t in tags:
        if t.startswith("v") and re.fullmatch(r"v\d+\.\d+\.\d+", t) and t != f"v{version}":
            return t
    return None


def notes(version: str) -> str:
    sec = section(version)
    parts = ["## ✨ What stands out", ""]
    parts += [f"- ✨ {p}" for p in highlights(sec)]
    parts += ["", "---", "", sec.rstrip(), ""]
    prev = previous_tag(version)
    if prev:
        parts += ["", f"**Full Changelog**: https://github.com/deziss/readyhai/"
                      f"compare/{prev}...v{version}"]
    return "\n".join(parts) + "\n"


def title(version: str) -> str:
    hl = highlights(section(version))
    if not hl:
        return f"ReadyHai v{version}"
    tagline = hl[0].split(" — ")[0].strip("*").strip()
    tagline = re.sub(r"\s*\([^)]*\)\s*$", "", tagline)  # drop trailing (path)s
    tagline = tagline[0].upper() + tagline[1:]
    return f"ReadyHai v{version} — {tagline}"


def main(argv: list[str]) -> int:
    want_title, args = False, argv[1:]
    if args and args[0] == "--title":
        want_title, args = True, args[1:]
    if not args or not re.fullmatch(r"\d+\.\d+\.\d+", args[0]):
        sys.exit(__doc__)
    out = title(args[0]) if want_title else notes(args[0])
    if not want_title and len(args) == 2:
        Path(args[1]).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
