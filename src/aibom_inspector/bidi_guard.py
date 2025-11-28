from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Iterable

BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u061c": "ARABIC LETTER MARK",
}


def _git_tracked_files() -> list[Path]:
    result = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True, text=True)
    return [Path(p) for p in result.stdout.split("\0") if p]


def find_bidi(text: str) -> set[str]:
    return {char for char in BIDI_CONTROLS if char in text}


def scan_file(path: Path) -> set[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return set()

    decoded = data.decode("utf-8", errors="ignore")
    return find_bidi(decoded)


def scan_paths(paths: Iterable[Path]) -> dict[Path, set[str]]:
    findings: dict[Path, set[str]] = {}
    for candidate in paths:
        found = scan_file(candidate)
        if found:
            findings[candidate] = found
    return findings


def _format_chars(chars: set[str]) -> str:
    return ", ".join(f"{BIDI_CONTROLS[ch]} (U+{ord(ch):04X})" for ch in sorted(chars))


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv
    paths = [Path(arg) for arg in argv[1:]] or _git_tracked_files()
    findings = scan_paths(paths)

    if findings:
        for path, chars in sorted(findings.items()):
            print(f"{path}: {_format_chars(chars)}", file=sys.stderr)
        print(
            "Bidirectional control characters detected; please remove them before committing.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
