import json
import os

import pytest

import sbom_common
import scan_all
from helpers import (BASELINE_EVENTS, F127, F128, FakeDocker, Result, RootOwned, bom_image_id, findings,
                     read_events)
from sbom_common import latest_scans


@pytest.fixture
def host(monkeypatch, tmp_path, db):
    """A machine for host mode: Docker (a FakeDocker, with no images yet), MongoDB and the
    Wazuh log."""
    docker = FakeDocker()
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(scan_all, "OUT_DIR", tmp_path / "out")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", str(tmp_path / "log" / "trivy-findings.jsonl"))
    monkeypatch.setattr(scan_all, "WAZUH_EPS", 0)
    monkeypatch.setattr(scan_all, "get_db", lambda: db)
    return docker


def test_read_inventory_skips_comments_and_duplicates(tmp_path):
    p = tmp_path / "inventory.txt"
    p.write_text("# images\npython:3.11-slim\n\npython:3.11-slim  # again\nalpine:3.20\n")
    assert scan_all.read_inventory(p) == ["python:3.11-slim", "alpine:3.20"]


def test_missing_inventory_file_is_an_error_not_a_full_host_scan(tmp_path):
    with pytest.raises(SystemExit) as e:
        scan_all.main([str(tmp_path / "typo.txt")])
    assert "not found" in str(e.value)


def test_local_images_lists_names_ids_and_digests_but_not_trivy(monkeypatch):
    docker = FakeDocker()
    docker.image("sha256:py", tags=["python:3.11-slim"], digests=["python@sha256:p1"])
    docker.image("sha256:tr", tags=["aquasec/trivy:latest", "trivy:sweri"])
    docker.image("sha256:mo", tags=["mongo:7"])
    docker.image("sha256:ap", tags=["localhost:5000/team/app:2"], digests=["localhost:5000/team/app@sha256:t1"])
    docker.image("sha256:old", digests=["registry.example.com/x@sha256:o1"])   # no tag left
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    assert scan_all.local_images() == [
        {"name": "python:3.11-slim", "id": "sha256:py", "digest_ref": "python@sha256:p1"},
        {"name": "mongo:7", "id": "sha256:mo", "digest_ref": None},
        {"name": "localhost:5000/team/app:2", "id": "sha256:ap",
         "digest_ref": "localhost:5000/team/app@sha256:t1"},
        {"name": None, "id": "sha256:old", "digest_ref": "registry.example.com/x@sha256:o1"},
    ]


def test_local_images_reports_docker_errors(monkeypatch):
    monkeypatch.setattr(scan_all.subprocess, "run", lambda *a, **k: Result(
        returncode=1, stderr="permission denied while trying to connect to the Docker daemon socket"))
    with pytest.raises(SystemExit) as e:
        scan_all.local_images()
    assert "docker group" in str(e.value)


def test_an_image_is_only_missing_when_docker_says_so(monkeypatch):
    answers = {"here:1": Result(stdout="sha256:abc\n"),
               "gone:1": Result(1, stderr="Error response from daemon: No such image: gone:1"),
               "down:1": Result(1, stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock")}
    monkeypatch.setattr(scan_all.subprocess, "run", lambda cmd, **k: answers[cmd[-1]])
    assert scan_all.image_id("here:1") == "sha256:abc"
    assert scan_all.image_id("gone:1") is None
    with pytest.raises(RuntimeError, match="couldn't ask Docker about down:1: Cannot connect"):
        scan_all.image_id("down:1")


def test_scan_command_reads_only_local_images_with_the_cache_and_a_partial_file(monkeypatch, tmp_path):
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
    assert cmd[cmd.index("--image-src") + 1] == "docker"         # never downloads the image itself
    assert cmd[cmd.index("--timeout") + 1] == "30m"
    assert cmd[-1] == "python:3.11-slim"

    # target: another reference to read the image by; the file is still named after the image
    monkeypatch.setattr(scan_all, "SCAN_TIMEOUT", "2h")
    out = scan_all.scan_image("python:3.11-slim", tmp_path, skip_db_update=True,
                              target="python@sha256:abc")
    assert out.name == "python_3.11-slim.json" and seen["cmd"][-1] == "python@sha256:abc"
    assert seen["cmd"][seen["cmd"].index("--timeout") + 1] == "2h"


def test_scan_timeout_must_be_a_duration(host, monkeypatch):
    for good in ("30m", "90m", "2h", "1h30m", "1.5h"):
        monkeypatch.setattr(scan_all, "SCAN_TIMEOUT", good)
        scan_all.check_settings()
    for bad in ("30", "2 hours", "30M", "0m", "0h0m"):
        monkeypatch.setattr(scan_all, "SCAN_TIMEOUT", bad)
        with pytest.raises(SystemExit, match="isn't a duration"):
            scan_all.check_settings()
    os.makedirs(os.path.dirname(scan_all.WAZUH_JSONL))            # as installation step 6 does
    with pytest.raises(SystemExit):                                # stops before scanning anything
        scan_all.main([])
    assert host.scans == []
    [summary] = read_events(scan_all.WAZUH_JSONL)
    assert summary["run_status"] == "error" and "SBOM_SCAN_TIMEOUT" in summary["errors"]


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


def test_main_end_to_end(host, capsys):
    host.image("sha256:app", tags=["example/app:1.0"])
    host.image("sha256:big", tags=["broken/image:1"], error="FATAL image scan error: context deadline exceeded")
    host.image("sha256:trivy", tags=["aquasec/trivy:latest"])
    log = scan_all.WAZUH_JSONL
    assert scan_all.main([]) == 1                                  # one image failed -> non-zero
    out = capsys.readouterr().out
    assert "context deadline exceeded" in out
    assert "(1 ok, 1 failed)" in out
    assert host.scans == ["sha256:app"] and host.pulls == []       # by image ID; not Trivy itself
    saved = json.loads((scan_all.OUT_DIR / "example_app_1.0.json").read_text())
    assert saved["metadata"]["component"]["name"] == "example/app:1.0"   # named after the image
    events = read_events(log)
    assert len(findings(log)) == BASELINE_EVENTS
    summary = events[-1]                                           # one summary, written last
    assert (summary["sbom_event"], summary["run_status"], summary["scanned"], summary["failed"]) == \
        ("scan_run", "failed", 1, 1)
    assert "broken/image:1" in summary["errors"] and "context deadline exceeded" in summary["errors"]

    assert scan_all.main([]) == 1                                  # second run: nothing new to send
    assert len(findings(log)) == BASELINE_EVENTS
    assert [e["sbom_event"] for e in read_events(log)].count("scan_run") == 2


def test_tags_of_one_image_are_scanned_once_under_one_name(host):
    host.image("sha256:a", tags=["example/app:latest", "example/app:1.0"])
    log = scan_all.WAZUH_JSONL
    assert scan_all.main([]) == 0
    assert host.scans == ["sha256:a"]                              # one scan for both tags
    assert len(findings(log)) == BASELINE_EVENTS
    assert {(e["image"], e["other_tags"]) for e in findings(log)} == {("example/app:1.0", "example/app:latest")}

    # A new build takes `latest`. The old image keeps 1.0 and the name it is reported under,
    # so nothing is sent for it again; the new one is reported under its own version.
    host.images["sha256:a"]["tags"].remove("example/app:latest")
    host.image("sha256:b", tags=["example/app:latest", "example/app:1.1"], fixture=F128)
    assert scan_all.main([]) == 0
    assert host.scans[1:] == ["sha256:a", "sha256:b"]
    assert {e["image"] for e in findings(log)[BASELINE_EVENTS:]} == {"example/app:1.1"}


def test_a_moving_tag_never_takes_a_new_build_away_from_its_own_name(host, db, tmp_path):
    """The previous version reported every tag separately, so `latest` is already in use. A
    new build is still reported under its version, not as a change to `latest` first and a
    second time under its version once `latest` moves on."""
    for name in ("example/app:1.0", "example/app:latest"):
        scan_all.ingest(db, name, F127, wazuh_log=str(tmp_path / "before.jsonl"), eps=0)
    host.image(bom_image_id(F127), tags=["example/app:1.0", "example/app:latest"])
    assert scan_all.main([]) == 0 and findings(scan_all.WAZUH_JSONL) == []   # nothing new
    for build, fixture in (("1.1", F128), ("1.2", F127)):
        for img in host.images.values():
            if "example/app:latest" in img["tags"]:
                img["tags"].remove("example/app:latest")
        host.image(f"sha256:build-{build}", tags=["example/app:latest", f"example/app:{build}"],
                   fixture=fixture)
        assert scan_all.main([]) == 0
    sent = findings(scan_all.WAZUH_JSONL)
    assert {e["image"] for e in sent} == {"example/app:1.1", "example/app:1.2"}
    assert all(e.get("cause") in (None, "baseline") for e in sent)      # each build reported once
    assert [e["image"] for e in sent if e.get("cve_id") == "CVE-2024-2398"] == ["example/app:1.1"]


def test_a_build_first_reported_under_a_moving_tag_isnt_reported_again_when_the_tag_moves_on(host):
    host.image("sha256:y", tags=["fox-desktop:optimized"])
    assert scan_all.main([]) == 0                                   # built, not versioned yet
    host.images["sha256:y"]["tags"].append("registry.example.com/fox:3.3.0")   # then tagged and pushed
    assert scan_all.main([]) == 0
    host.images["sha256:y"]["tags"].remove("fox-desktop:optimized")
    host.image("sha256:z", tags=["fox-desktop:optimized"], fixture=F128)         # the next build
    assert scan_all.main([]) == 0
    sent = findings(scan_all.WAZUH_JSONL)
    assert len([e for e in sent if e["image_id"] == "sha256:y"]) == BASELINE_EVENTS   # y: once
    z = [e for e in sent if e["image_id"] == "sha256:z"]
    assert {e["image"] for e in z} == {"fox-desktop:optimized"}
    assert z and all(e.get("cause") != "baseline" for e in z)       # z: what changed since y


def test_an_image_whose_reported_tag_is_removed_carries_on_under_its_other_name(host, db):
    host.image("sha256:x", tags=["registry.example.com/fox:3.2.0", "fox-desktop:optimized"])
    assert scan_all.main([]) == 0
    host("docker rmi registry.example.com/fox:3.2.0".split())
    assert scan_all.main([]) == 0
    assert len(findings(scan_all.WAZUH_JSONL)) == BASELINE_EVENTS            # nothing sent again
    assert [s["image"] for s in latest_scans(db)] == ["fox-desktop:optimized"]  # exported once
    assert db.vuln_state.count_documents({"image": "registry.example.com/fox:3.2.0"}) == 0


def test_new_findings_after_a_record_moved_are_put_down_to_vulnerability_data(host):
    """The record that moved with the image says which image it describes, so a new CVE for
    the unchanged image is a db_update, as it would have been under its old name."""
    host.image("sha256:y", tags=["fox-desktop:optimized"])
    assert scan_all.main([]) == 0
    host.images["sha256:y"]["tags"] = ["registry.example.com/fox:3.3.0"]
    host.images["sha256:y"]["fixture"] = F128                       # same image, newer data
    assert scan_all.main([]) == 0
    new = [e for e in findings(scan_all.WAZUH_JSONL)[BASELINE_EVENTS:] if e["sbom_event"] == "vulnerability"]
    assert [(e["image"], e["cve_id"], e["cause"]) for e in new] == \
        [("registry.example.com/fox:3.3.0", "CVE-2024-2398", "db_update")]


def test_an_image_with_no_packages_never_takes_another_images_record(host, db, tmp_path):
    """Names are settled by what each one last reported, not by whether it holds any rows,
    and every record is read before any is moved."""
    empty = tmp_path / "scratch.cdx.json"
    bom = json.loads(F127.read_text())
    bom["components"], bom["vulnerabilities"], bom["dependencies"] = [], [], []
    empty.write_text(json.dumps(bom))
    host.image("sha256:x", tags=["a-app:1"])
    host.image("sha256:s", tags=["b-app:1"], fixture=empty)
    assert scan_all.main([]) == 0
    host.images["sha256:x"]["tags"] = ["b-app:1"]                  # b-app:1 moves to x, s renamed
    host.images["sha256:s"]["tags"] = ["c-app:1"]
    assert scan_all.main([]) == 0
    assert len(findings(scan_all.WAZUH_JSONL)) == BASELINE_EVENTS  # nothing more for either
    assert db.component_state.count_documents({"image": "c-app:1"}) == 0
    assert db.component_state.count_documents({"image": "b-app:1"}) == 8


def test_a_moved_record_still_says_which_image_it_describes_after_a_failed_scan(host):
    host.image("sha256:y", tags=["fox-desktop:optimized"])
    assert scan_all.main([]) == 0
    host.images["sha256:y"]["tags"] = ["registry.example.com/fox:3.3.0"]
    host.images["sha256:y"]["error"] = "FATAL image scan error: context deadline exceeded"
    assert scan_all.main([]) == 1                                   # record moved, scan failed
    host.images["sha256:y"].update(error=None, fixture=F128)        # same image, newer data
    assert scan_all.main([]) == 0
    new = [e for e in findings(scan_all.WAZUH_JSONL)[BASELINE_EVENTS:] if e["sbom_event"] == "vulnerability"]
    assert [(e["cve_id"], e["cause"]) for e in new] == [("CVE-2024-2398", "db_update")]


def test_scans_work_as_the_scanners_own_user_although_trivy_writes_as_root(host, db, monkeypatch):
    owned = RootOwned(monkeypatch, host)
    host.image("sha256:x", tags=["fox-desktop:optimized"])
    host.image("sha256:b", tags=["b-app:1"], fixture=F128)
    assert scan_all.main([]) == 0
    assert len(findings(scan_all.WAZUH_JSONL)) == BASELINE_EVENTS + 13
    saved = json.loads((scan_all.OUT_DIR / "fox-desktop_optimized.json").read_text())
    assert saved["metadata"]["component"]["name"] == "fox-desktop:optimized"

    # x's record moves to b-app:1, whose SBOM file is Trivy's, as the previous version left them
    owned.paths.add(os.path.realpath(scan_all.OUT_DIR / "b-app_1.json"))
    host.images["sha256:b"]["tags"] = []
    host.images["sha256:x"]["tags"] = ["b-app:1"]
    host.images["sha256:x"]["error"] = "FATAL image scan error: context deadline exceeded"
    assert scan_all.main([]) == 1
    moved = db.scans.find_one({"image": "b-app:1", "carried_from": "fox-desktop:optimized"})
    assert moved["source_file"] == str(scan_all.OUT_DIR / "b-app_1.json")
    assert [s["image"] for s in latest_scans(db) if s["image_id"] == "sha256:x"] == ["b-app:1"]


def test_a_moved_record_is_marked_as_a_move_not_a_scan(host, db, monkeypatch, capsys):
    host.image("sha256:x", tags=["fox-desktop:optimized", "other:1"])
    assert scan_all.main([]) == 0
    host.images["sha256:x"]["tags"] = ["registry.example.com/fox:3.3.0"]
    host.images["sha256:x"]["error"] = "FATAL image scan error: context deadline exceeded"
    monkeypatch.setattr(scan_all.shutil, "copyfile", lambda src, dst: (_ for _ in ()).throw(OSError("disk full")))
    assert scan_all.main([]) == 1
    moved = db.scans.find_one({"carried_from": {"$exists": True}}, {"_id": 0})
    assert moved.keys() == {"host", "image", "image_id", "scanned_at", "carried_from", "source_file"}
    assert (moved["image"], moved["source_file"]) == ("registry.example.com/fox:3.3.0", None)  # copy failed
    import export_cyclonedx
    monkeypatch.setattr(export_cyclonedx, "get_db", lambda: db)
    monkeypatch.setattr(export_cyclonedx, "OUT_DIR", scan_all.OUT_DIR)
    assert export_cyclonedx.main(["--output", str(scan_all.OUT_DIR / "all.cdx.json")]) == 1
    assert "skipped registry.example.com/fox:3.3.0: no saved SBOM" in capsys.readouterr().out


def test_inventory_names_are_the_ones_docker_lists(host, db, tmp_path):
    host.image("sha256:n", tags=["nginx:latest"])
    inventory = tmp_path / "images.txt"
    inventory.write_text("nginx\ndocker.io/library/nginx:latest\n")
    for _ in range(2):
        assert scan_all.main([str(inventory)]) == 0
        assert scan_all.main([]) == 0
    assert db.scans.count_documents({"carried_from": {"$exists": True}}) == 0
    assert {e["image"] for e in findings(scan_all.WAZUH_JSONL)} == {"nginx:latest"}
    assert scan_all.familiar("registry.example.com:5000/team/app") == "registry.example.com:5000/team/app:latest"
    assert scan_all.familiar("nginx@sha256:abc") == "nginx@sha256:abc"


def test_upgrading_from_one_record_per_tag_sends_nothing_again(host, db, tmp_path):
    """The previous version kept a record for every tag. The image is now reported under one
    name and the other names' records are dropped; nothing is sent again, then or later when
    the reported tag is removed."""
    for name in ("fox-desktop:optimized", "registry.example.com/fox:3.2.0"):
        scan_all.ingest(db, name, F127, wazuh_log=str(tmp_path / "before.jsonl"), eps=0)
    x = bom_image_id(F127)
    host.image(x, tags=["fox-desktop:optimized", "registry.example.com/fox:3.2.0"])
    assert scan_all.main([]) == 0
    assert db.vuln_state.count_documents({"image": "fox-desktop:optimized"}) == 0
    assert [s["image"] for s in latest_scans(db)] == ["registry.example.com/fox:3.2.0"]
    host("docker rmi registry.example.com/fox:3.2.0".split())
    assert scan_all.main([]) == 0
    assert findings(scan_all.WAZUH_JSONL) == []
    assert [s["image"] for s in latest_scans(db)] == ["fox-desktop:optimized"]


def test_a_tag_moving_during_the_run_doesnt_change_what_is_scanned(host):
    """Images are scanned by ID, so a build that takes a tag mid-run isn't scanned twice."""
    host.image("sha256:x", tags=["example/app:2.0"])
    host.image("sha256:y", tags=["example/app:2.1"], fixture=F128)
    real = host.trivy

    def build_lands(cmd):                                           # 2.0 moves to y first
        if "example/app:2.0" in host.images["sha256:x"]["tags"]:
            host.images["sha256:x"]["tags"].remove("example/app:2.0")
            host.images["sha256:y"]["tags"].append("example/app:2.0")
        return real(cmd)
    host.trivy = build_lands
    assert scan_all.main([]) == 0
    assert host.scans == ["sha256:x", "sha256:y"]
    by_image = {e["image"]: e["image_id"] for e in findings(scan_all.WAZUH_JSONL)}
    assert by_image == {"example/app:2.0": "sha256:x", "example/app:2.1": "sha256:y"}


def test_the_name_an_image_is_reported_under(db):
    # a fixed version before latest (latest moves on to the next build), then a name with the
    # registry's address, then A to Z
    assert scan_all.choose_primary(db, "node-01", ["app:latest", "app:v2"]) == "app:v2"
    assert scan_all.choose_primary(db, "node-01", ["app:v2", "acr.example.io/app:v2"]) == "acr.example.io/app:v2"
    assert scan_all.choose_primary(db, "node-01", ["app:1", "localhost:5000/app:1"]) == "localhost:5000/app:1"
    assert scan_all.choose_primary(db, "node-01", ["acr.example.io/app:latest", "app:optimized"]) == "app:optimized"
    assert scan_all.choose_primary(db, "node-01", ["team/app:2", "team/app:10"]) == "team/app:10"


def test_an_image_already_reported_keeps_its_name_when_it_gains_a_tag(host):
    host.image("sha256:a", tags=["example/app:latest"])
    assert scan_all.main([]) == 0
    host.images["sha256:a"]["tags"].append("example/app:1.0")
    assert scan_all.main([]) == 0
    assert {e["image"] for e in findings(scan_all.WAZUH_JSONL)} == {"example/app:latest"}
    assert len(findings(scan_all.WAZUH_JSONL)) == BASELINE_EVENTS     # nothing sent twice


def test_listed_images_must_be_on_this_machine_and_are_never_downloaded(host, tmp_path):
    host.image("sha256:a", tags=["example/app:latest"])
    inventory = tmp_path / "images.txt"
    inventory.write_text("example/app\nghost/app:1\n")            # example/app means example/app:latest
    assert scan_all.main([str(inventory)]) == 1
    assert host.scans == ["sha256:a"] and host.pulls == []
    summary = read_events(scan_all.WAZUH_JSONL)[-1]
    assert (summary["scanned"], summary["failed"]) == (1, 1)
    assert "ghost/app:1: not among this machine's images" in summary["errors"]


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


def test_env_file_fills_in_settings_but_the_environment_wins(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# MongoDB\n\nSBOM_TEST_URI='mongodb://u:p#w@db:27017/sbom'\n"
                   "export SBOM_TEST_DB = scans\nSBOM_TEST_KEEP=from-file\nnot a setting\n")
    for key in ("SBOM_TEST_URI", "SBOM_TEST_DB"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SBOM_TEST_KEEP", "from-environment")
    sbom_common.load_env_file(env)
    assert os.environ["SBOM_TEST_URI"] == "mongodb://u:p#w@db:27017/sbom"   # '#' in a password is kept
    assert os.environ["SBOM_TEST_DB"] == "scans"
    assert os.environ["SBOM_TEST_KEEP"] == "from-environment"
    sbom_common.load_env_file(tmp_path / "no-such-file")                    # no .env is fine


def test_an_inventory_name_docker_cant_look_up_says_why(host, tmp_path, monkeypatch):
    def docker(cmd, **kwargs):
        if cmd[-1] == "Bad/Name:1":
            return Result(1, stderr="invalid reference format: repository name must be lowercase")
        return host(cmd, **kwargs)
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    inventory = tmp_path / "images.txt"
    inventory.write_text("Bad/Name:1\n")
    assert scan_all.main([str(inventory)]) == 1
    assert "Bad/Name:1: couldn't ask Docker about Bad/Name:1: invalid reference format" in \
        read_events(scan_all.WAZUH_JSONL)[-1]["errors"]


def test_host_mode_reports_docker_being_down(monkeypatch, tmp_path):
    log = tmp_path / "events.jsonl"
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", str(log))
    monkeypatch.setattr(scan_all, "local_images",
                        lambda: (_ for _ in ()).throw(SystemExit("'docker images' failed: daemon down")))
    with pytest.raises(SystemExit):
        scan_all.main([])
    [summary] = [json.loads(line) for line in log.read_text().splitlines()]
    assert (summary["scanner_mode"], summary["run_status"]) == ("host", "error")
    assert "daemon down" in summary["errors"]
