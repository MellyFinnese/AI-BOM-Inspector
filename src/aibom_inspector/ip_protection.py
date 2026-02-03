from __future__ import annotations

import ast
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IpProtectionResult:
    path: str
    output_path: str
    action: str
    status: str
    message: str | None = None


def _strip_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                if isinstance(node.body[0].value.value, str):
                    node.body = node.body[1:]
    return tree


def obfuscate_python_file(path: Path, output_path: Path) -> IpProtectionResult:
    try:
        source = path.read_text()
        tree = ast.parse(source)
        tree = _strip_docstrings(tree)
        obfuscated = ast.unparse(tree)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(obfuscated)
        return IpProtectionResult(
            path=str(path),
            output_path=str(output_path),
            action="obfuscate",
            status="ok",
        )
    except Exception as exc:
        return IpProtectionResult(
            path=str(path),
            output_path=str(output_path),
            action="obfuscate",
            status="error",
            message=str(exc),
        )


def strip_symbols(path: Path, output_path: Path, strip_tool: str | None = None) -> IpProtectionResult:
    tool = strip_tool or shutil.which("strip")
    if not tool:
        return IpProtectionResult(
            path=str(path),
            output_path=str(output_path),
            action="strip",
            status="error",
            message="strip tool not found",
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [tool, "--strip-unneeded", "-o", str(output_path), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        return IpProtectionResult(
            path=str(path),
            output_path=str(output_path),
            action="strip",
            status="error",
            message=str(exc),
        )
    if result.returncode != 0:
        return IpProtectionResult(
            path=str(path),
            output_path=str(output_path),
            action="strip",
            status="error",
            message=result.stderr.strip() or "strip failed",
        )
    return IpProtectionResult(
        path=str(path),
        output_path=str(output_path),
        action="strip",
        status="ok",
    )


def protect_ip(
    *,
    obfuscate_paths: list[Path],
    strip_paths: list[Path],
    output_dir: Path,
    strip_tool: str | None = None,
) -> list[IpProtectionResult]:
    results: list[IpProtectionResult] = []
    for path in obfuscate_paths:
        output_path = output_dir / "obfuscated" / path.name
        results.append(obfuscate_python_file(path, output_path))
    for path in strip_paths:
        output_path = output_dir / "stripped" / path.name
        results.append(strip_symbols(path, output_path, strip_tool=strip_tool))
    return results
