from __future__ import annotations

import subprocess

import pytest

from tests.e2e import test_real_e2e


def _completed_process(*, returncode: int, stderr: str = "", stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["docker", "compose", "up"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_ensure_docker_cluster_skips_when_rust_checkout_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(test_real_e2e, "is_docker_running", lambda: True)
    monkeypatch.setattr(test_real_e2e, "is_dcpp_cluster_running", lambda: False)
    monkeypatch.setattr(
        test_real_e2e.subprocess,
        "run",
        lambda *args, **kwargs: _completed_process(
            returncode=1,
            stderr='unable to prepare context: path "/home/runner/work/Pypin/dcpp-rust" not found',
        ),
    )

    with pytest.raises(pytest.skip.Exception, match="Missing external dcpp-rust checkout"):
        test_real_e2e.ensure_docker_cluster("unit test")


def test_ensure_docker_cluster_raises_for_unknown_compose_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(test_real_e2e, "is_docker_running", lambda: True)
    monkeypatch.setattr(test_real_e2e, "is_dcpp_cluster_running", lambda: False)
    monkeypatch.setattr(
        test_real_e2e.subprocess,
        "run",
        lambda *args, **kwargs: _completed_process(
            returncode=1,
            stderr="compose build failed for unrelated reason",
        ),
    )

    with pytest.raises(RuntimeError, match="compose build failed for unrelated reason"):
        test_real_e2e.ensure_docker_cluster("unit test")
