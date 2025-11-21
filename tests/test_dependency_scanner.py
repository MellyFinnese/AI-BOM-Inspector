import json
import sys
from pathlib import Path

from aibom_inspector.dependency_scanner import (
    enrich_with_osv,
    parse_requirement_line,
    parse_sbom,
    scan_go_mod,
    scan_package_json,
    scan_package_lock,
    scan_pom,
    scan_pyproject,
    scan_requirements,
)
from aibom_inspector.types import DependencyInfo


def test_parse_requirement_flags_unpinned_and_pre_release():
    info = parse_requirement_line("sample")
    assert info
    assert any("MISSING_PIN" in issue.message for issue in info.issues)

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


def test_scan_package_json_flags_loose_ranges(tmp_path: Path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        """
{
  "dependencies": {"lodash": "^4.17.21"},
  "devDependencies": {"vite": "~5.0.0"}
}
"""
    )

    deps = scan_package_json(pkg)
    assert len(deps) == 2
    assert any("LOOSE_PIN" in issue.message for issue in deps[0].issues)


def test_scan_package_lock_flags_missing_pin(tmp_path: Path):
    pkg_lock = tmp_path / "package-lock.json"
    pkg_lock.write_text(
        json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21"}}})
    )

    deps = scan_package_lock(pkg_lock)
    assert deps[0].name.endswith("lodash")
    assert deps[0].issues == []


def test_scan_go_mod_reads_requirements(tmp_path: Path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        """
module example.com/demo

require (
    github.com/pkg/errors v0.9.1
)
"""
    )

    deps = scan_go_mod(go_mod)
    assert deps[0].name == "github.com/pkg/errors"
    assert deps[0].source == "go.mod"


def test_scan_pom_reads_dependencies(tmp_path: Path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        """
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.20</version>
    </dependency>
  </dependencies>
</project>
"""
    )

    deps = scan_pom(pom)
    assert deps[0].name == "org.springframework:spring-core"


def test_parse_sbom_and_enrich_with_osv(monkeypatch, tmp_path: Path):
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "demo", "version": "1.0.0", "licenses": [{"license": {"id": "MIT"}}]}
        ],
    }
    sbom_path = tmp_path / "bom.json"
    sbom_path.write_text(json.dumps(cyclonedx))

    deps = parse_sbom(sbom_path)
    assert deps[0].license == "MIT"

    class DummyResponse:
        status_code = 200

        def json(self):
            return {"vulns": [{"id": "CVE-TEST", "summary": "demo vuln"}]}

    class DummyRequests:
        @staticmethod
        def post(*args, **kwargs):
            return DummyResponse()

    monkeypatch.setitem(sys.modules, "requests", DummyRequests)

    enriched = enrich_with_osv([DependencyInfo(name="demo", version="1.0.0", source="requirements.txt", issues=[])])
    assert any("CVE" in issue.message for issue in enriched[0].issues)
