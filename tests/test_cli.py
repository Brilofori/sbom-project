import json

import pytest

import scan_all


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_read_inventory_skips_comments_and_duplicates(tmp_path):
    p = tmp_path / "inventory.txt"
    p.write_text("# images\npython:3.11-slim\n\npython:3.11-slim  # again\nalpine:3.20\n")
    assert scan_all.read_inventory(p) == ["python:3.11-slim", "alpine:3.20"]


def test_missing_inventory_file_is_an_error_not_a_full_host_scan(tmp_path):
    with pytest.raises(SystemExit) as e:
        scan_all.main([str(tmp_path / "typo.txt")])
    assert "not found" in str(e.value)


def test_discovery_skips_only_trivy(monkeypatch):
    listing = "python:3.11-slim\naquasec/trivy:latest\ntrivy:sweri\nmongo:7\n<none>:<none>\nlocalhost:5000/team/app:2\n"
    monkeypatch.setattr(scan_all.subprocess, "run", lambda *a, **k: Result(stdout=listing))
    assert scan_all.discover_images() == ["localhost:5000/team/app:2", "mongo:7", "python:3.11-slim"]


def test_discovery_reports_docker_errors(monkeypatch):
    monkeypatch.setattr(scan_all.subprocess, "run", lambda *a, **k: Result(
        returncode=1, stderr="permission denied while trying to connect to the Docker daemon socket"))
    with pytest.raises(SystemExit) as e:
        scan_all.discover_images()
    assert "docker group" in str(e.value)


def test_scan_command_uses_cache_pinned_image_and_partial_file(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        (tmp_path / "python_3.11-slim.json.partial").write_text('{"bomFormat": "CycloneDX"}')
        return Result()

    monkeypatch.setattr(scan_all.subprocess, "run", fake_run)
    out = scan_all.scan_image("python:3.11-slim", tmp_path, skip_db_update=True)
    assert out.name == "python_3.11-slim.json" and "CycloneDX" in out.read_text()
    assert not (tmp_path / "python_3.11-slim.json.partial").exists()
    cmd = seen["cmd"]
    assert "trivy-cache:/root/.cache/trivy" in cmd and "--skip-db-update" in cmd
    assert scan_all.TRIVY_IMAGE in cmd and "@sha256:" in scan_all.TRIVY_IMAGE
    assert cmd[-1] == "python:3.11-slim"


def test_failed_scan_keeps_the_last_good_sbom(monkeypatch, tmp_path):
    good = tmp_path / "python_3.11-slim.json"
    good.write_text("last good")
    monkeypatch.setattr(scan_all.subprocess, "run",
                        lambda *a, **k: Result(returncode=1, stderr="INFO x\nFATAL boom"))
    with pytest.raises(scan_all.ScanError, match="FATAL boom"):
        scan_all.scan_image("python:3.11-slim", tmp_path, skip_db_update=True)
    assert good.read_text() == "last good"


def test_prepare_trivy_downloads_db_once_and_reads_versions(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[-3:] == ["version", "--format", "json"]:
            return Result(stdout=json.dumps({"Version": "0.74.0", "VulnerabilityDB": {
                "Version": 2, "UpdatedAt": "2026-09-23T06:12:32.1Z"}}))
        return Result()

    monkeypatch.setattr(scan_all.subprocess, "run", fake_run)
    assert scan_all.prepare_trivy() == ("0.74.0", "2026-09-23T06:12:32.1Z", True)
    assert "--download-db-only" in calls[0]


def test_unwritable_wazuh_log_stops_before_scanning(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    with pytest.raises(SystemExit) as e:
        scan_all.check_wazuh_log(str(blocker / "sbom" / "x.jsonl"))
    assert "sudo chown" in str(e.value)


def test_main_end_to_end(monkeypatch, tmp_path, db, capsys):
    import shutil
    from pathlib import Path

    from helpers import BASELINE_EVENTS, F127, read_events

    log = tmp_path / "log" / "trivy-findings.jsonl"
    monkeypatch.setattr(scan_all, "OUT_DIR", tmp_path / "out")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", str(log))
    monkeypatch.setattr(scan_all, "get_db", lambda: db)

    def fake_docker(cmd, **kwargs):
        if cmd[:2] == ["docker", "images"]:
            return Result(stdout="example/app:1.0\nbroken/image:1\naquasec/trivy:latest\n")
        if "--download-db-only" in cmd:
            return Result()
        if cmd[-3:] == ["version", "--format", "json"]:
            return Result(stdout='{"Version": "0.74.0", "VulnerabilityDB": {"UpdatedAt": "2026-09-23"}}')
        if cmd[-1] == "broken/image:1":
            return Result(returncode=1, stderr="INFO ...\nFATAL unable to find the specified image")
        out_dir = next(m for m in cmd if m.endswith(":/out")).rsplit(":", 1)[0]
        partial = cmd[cmd.index("--output") + 1].split("/out/", 1)[1]
        shutil.copy(F127, Path(out_dir) / partial)
        return Result()

    monkeypatch.setattr(scan_all.subprocess, "run", fake_docker)
    assert scan_all.main([]) == 1                                  # one image failed -> non-zero
    out = capsys.readouterr().out
    assert "FATAL unable to find the specified image" in out
    assert "(1 ok, 1 failed)" in out
    assert (tmp_path / "out" / "example_app_1.0.json").exists()
    assert (tmp_path / "out" / "report_example_app_1.0.md").exists()
    assert len(read_events(str(log))) == BASELINE_EVENTS

    assert scan_all.main([]) == 1                                  # second run: nothing new to send
    assert len(read_events(str(log))) == BASELINE_EVENTS


def test_db_download_timeout_does_not_hang_the_run(monkeypatch):
    import subprocess

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))

    monkeypatch.setattr(scan_all.subprocess, "run", fake_run)
    assert scan_all.prepare_trivy() == ("unknown", None, False)


def test_unwritable_out_dir_stops_before_scanning(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    with pytest.raises(SystemExit) as e:
        scan_all.check_out_dir(blocker / "out")
    assert "sudo chown -R" in str(e.value)
