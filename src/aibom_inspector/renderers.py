from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .attestation import compute_output_hash
from .reporting import write_report
from .types import Report


@dataclass(frozen=True)
class RenderedOutputs:
    rendered: str
    report_path: Path | None
    report_hash: str
    output_hashes: dict[str, str]
    signature_text: str | None
    markdown_payload: str | None
    sarif_payload: str | None


def render_report_outputs(
    report: Report,
    fmt: str,
    *,
    output: str | None,
    sbom_output: str | None,
    markdown_output: str | None,
    sarif_output: str | None,
    sign_report: bool,
) -> RenderedOutputs:
    report_path = None
    if output:
        report_path = Path(output)
    elif sbom_output and fmt.lower() in {"cyclonedx", "spdx"}:
        report_path = Path(sbom_output)

    rendered = write_report(report, fmt, report_path)

    markdown_payload = None
    if markdown_output:
        markdown_payload = write_report(report, "markdown", Path(markdown_output))

    sarif_payload = None
    if sarif_output:
        sarif_payload = write_report(report, "sarif", Path(sarif_output))

    if (
        sbom_output
        and fmt.lower() in {"cyclonedx", "spdx"}
        and (report_path is None or Path(sbom_output) != report_path)
    ):
        write_report(report, fmt, Path(sbom_output))

    signature_text = None
    if sign_report:
        digest = hashlib.sha256(rendered.encode()).hexdigest()
        sig_path = (report_path or Path(f"aibom-report.{fmt}")).with_suffix(
            (report_path or Path(f"aibom-report.{fmt}")).suffix + ".sha256"
        )
        sig_path.parent.mkdir(parents=True, exist_ok=True)
        sig_path.write_text(digest)
        signature_text = digest

    output_hashes: dict[str, str] = {}
    report_hash = compute_output_hash(rendered)
    output_hashes[str(report_path or Path(f"aibom-report.{fmt}"))] = report_hash
    if markdown_output and markdown_payload is not None:
        output_hashes[str(Path(markdown_output))] = compute_output_hash(markdown_payload)
    if sarif_output and sarif_payload is not None:
        output_hashes[str(Path(sarif_output))] = compute_output_hash(sarif_payload)

    return RenderedOutputs(
        rendered=rendered,
        report_path=report_path,
        report_hash=report_hash,
        output_hashes=output_hashes,
        signature_text=signature_text,
        markdown_payload=markdown_payload,
        sarif_payload=sarif_payload,
    )
