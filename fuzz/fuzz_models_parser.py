"""Atheris fuzz target for model manifest parsing.

Run locally with:
  python -m fuzz.fuzz_models_parser -runs=10000
The target is optional and intentionally isolated from normal test dependencies.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

try:
    import atheris  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise SystemExit("install the optional 'fuzz' dependencies to run this target") from exc

from aibom_inspector.model_inspector import scan_models_from_file


def test_one_input(data: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="aibom-fuzz-") as tmp:
        path = Path(tmp) / "models.json"
        path.write_bytes(data[:2 * 1024 * 1024])
        scan_models_from_file(path, max_bytes=2 * 1024 * 1024)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
