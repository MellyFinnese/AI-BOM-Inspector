from __future__ import annotations

import pickletools
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional


DANGEROUS_NAMES = {
    "system",
    "popen",
    "popen2",
    "popen3",
    "popen4",
    "call",
    "check_call",
    "check_output",
    "eval",
    "exec",
    "spawn",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
}

DANGEROUS_MODULES = {"os", "posix", "subprocess", "builtins"}


@dataclass
class PickleFinding:
    opcode: str
    module: Optional[str]
    name: Optional[str]


@dataclass
class PickleScanResult:
    path: Path
    findings: List[PickleFinding] = field(default_factory=list)

    @property
    def suspected(self) -> bool:
        return bool(self.findings)

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "suspected": self.suspected,
            "findings": [f.__dict__ for f in self.findings],
        }


class PickleScanError(Exception):
    """Base class for pickle scanning errors."""


class PickleFileTooLargeError(PickleScanError):
    """Raised when a pickle exceeds a configured maximum size."""

    def __init__(self, path: Path, max_bytes: int, actual_size: int) -> None:
        super().__init__(f"Pickle file '{path}' is {actual_size} bytes; exceeds limit of {max_bytes} bytes")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.actual_size = actual_size


def _is_dangerous(module: Optional[str], name: Optional[str]) -> bool:
    module_l = (module or "").lower()
    name_l = (name or "").lower()
    if name_l in DANGEROUS_NAMES and (not module_l or module_l in DANGEROUS_MODULES):
        return True
    if module_l in {"builtins", "__builtin__"} and name_l in {"eval", "exec"}:
        return True
    return False


def _scan_globals(data: bytes) -> List[PickleFinding]:
    stack: List[str] = []
    findings: List[PickleFinding] = []

    for opcode, arg, _ in pickletools.genops(data):
        if isinstance(arg, str):
            stack.append(arg)
            if len(stack) > 1024:
                stack = stack[-256:]

        module: Optional[str] = None
        name: Optional[str] = None

        if opcode.name == "GLOBAL" and isinstance(arg, str):
            if " " in arg:
                module, name = arg.split(" ", 1)
            elif "\n" in arg:
                module, name = arg.split("\n", 1)
            else:
                module = arg
        elif opcode.name == "STACK_GLOBAL":
            name = stack.pop() if stack else None
            module = stack.pop() if stack else None

        if module is None and name is None:
            continue

        if _is_dangerous(module, name):
            findings.append(PickleFinding(opcode=opcode.name, module=module, name=name))

    return findings


def inspect_pickle_file(path: Path | str, max_bytes: int | None = 10_000_000) -> PickleScanResult:
    path = Path(path)
    if max_bytes is not None and max_bytes > 0:
        file_size = path.stat().st_size
        if file_size > max_bytes:
            raise PickleFileTooLargeError(path, max_bytes, file_size)

    data = path.read_bytes()
    findings = _scan_globals(data)
    return PickleScanResult(path=path, findings=findings)


def inspect_pickle_files(
    paths: Iterable[Path | str], *, max_bytes: int | None = 10_000_000
) -> List[PickleScanResult]:
    results: List[PickleScanResult] = []
    for candidate in paths:
        results.append(inspect_pickle_file(candidate, max_bytes=max_bytes))
    return results
