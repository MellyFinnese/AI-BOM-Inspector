import shutil
import pickle
from pathlib import Path
import pytest

from subprocess import CalledProcessError, run


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not available")
def test_pickle_sandbox_runner_build_and_run(tmp_path: Path):
    # Additional runtime check: docker daemon must be reachable
    try:
        r = run(["docker", "info"], capture_output=True)
        if r.returncode != 0:
            pytest.skip("Docker daemon not available: skip sandbox integration test")
    except Exception:
        pytest.skip("Docker daemon not available: skip sandbox integration test")
    data = pickle.dumps({"a": 1})
    target = tmp_path / "sample.pkl"
    target.write_bytes(data)

    out = tmp_path / "trace.json"
    runner = Path.cwd() / "scripts" / "pickle_sandbox_runner.py"
    # Build and run the sandbox (may require docker privileges in the runner environment)
    res = run([str(runner), str(target), "--output", str(out)], check=False)
    assert res.returncode == 0
    assert out.exists()
    content = out.read_text()
    assert "events" in content
