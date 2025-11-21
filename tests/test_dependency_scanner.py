from pathlib import Path

from aibom_inspector.dependency_scanner import parse_requirement_line, scan_pyproject, scan_requirements


def test_parse_requirement_flags_unpinned_and_pre_release():
    info = parse_requirement_line("sample")
    assert info
    assert any(issue.message == "Unpinned dependency" for issue in info.issues)

    pre = parse_requirement_line("experimental==0.3.0")
    assert pre
    assert any("unstable" in issue.message for issue in pre.issues)


def test_scan_requirements_reads_pins(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("click==8.1.7\nrequests>=2.0.0\n# comment\n")

    deps = scan_requirements(req_file)
    assert len(deps) == 2
    assert deps[0].name == "click"
    assert deps[0].issues == []
    assert any("LOOSE_PIN" in issue.message for issue in deps[1].issues)


def test_known_vulnerability_is_flagged(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.25.8\n")

    deps = scan_requirements(req_file)
    vuln_issue = deps[0].issues[0].message
    assert "KNOWN_VULN" in vuln_issue


def test_scan_pyproject_reads_optional_dependencies(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["jinja2==3.1.4"]

[project.optional-dependencies]
hf = ["transformers>=4.0.0"]
        """
    )

    deps = scan_pyproject(pyproject)
    assert {d.name for d in deps} == {"jinja2", "transformers"}
    hf = next(dep for dep in deps if dep.name == "transformers")
    assert hf.source == "pyproject.toml"
    assert any("LOOSE_PIN" in issue.message for issue in hf.issues)


def test_enrich_with_osv(monkeypatch):
    deps = [parse_requirement_line("click==8.1.7"), parse_requirement_line("requests>=2.0.0")]

    def fake_query(batch):
        assert batch
        return [{"vulns": [{"id": "CVE-2024-0001", "summary": "demo"}]}, {}]

    monkeypatch.setattr("aibom_inspector.dependency_scanner._query_osv", fake_query)
    enriched = enrich_with_osv([d for d in deps if d])
    issue_messages = [i.message for i in enriched[0].issues]
    assert any("CVE" in msg for msg in issue_messages)


def test_parse_sbom_file(tmp_path: Path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text("""{"components": [{"name": "fastapi", "version": "0.110.0"}]}""")
    deps = parse_sbom_file(sbom)
    assert deps[0].name == "fastapi"
