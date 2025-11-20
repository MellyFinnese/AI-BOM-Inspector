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
    assert any(issue.message.startswith("Version is not strictly pinned") for issue in deps[1].issues)


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
    assert any(issue.message.startswith("Version is not strictly pinned") for issue in hf.issues)
