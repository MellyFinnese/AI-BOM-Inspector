import sys
from pathlib import Path

# Ensure src package is importable without installation
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.exists():
    sys.path.insert(0, str(SRC))
