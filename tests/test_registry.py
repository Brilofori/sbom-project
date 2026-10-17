"""Registry-mode helpers and the v2 registry client, against a local mock registry."""
import base64
import http.server
import json
import subprocess
import threading
import urllib.parse
from types import SimpleNamespace

import mongomock
import pytest

import scan_all
import scan_registry as sr
from helpers import (BASELINE_EVENTS, F127, F128, ONLY_IN_F127, ONLY_IN_F128, FakeDocker, FakeRegistry,
                     RootOwned, by_kind, findings, read_events)
from sbom_common import redact

TAGS = ["1.9.0", "1.10.0", "1.10.0-rc1", "2.0.0", "latest"]
CREDS = ("robot$scanner", "tok3n")
REPOS = ["proj/app", "proj/worker", "test/scratch"]
AMD = {"os": "linux", "architecture": "amd64"}
ARM = {"os": "linux", "architecture": "arm64"}
INDEXES = {"multi": [AMD, ARM], "armonly": [ARM]}   # tags served as multi-platform indexes


class MockRegistry(http.server.BaseHTTPRequestHandler):
    """Harbor/GitLab-style: Bearer challenge, token endpoint, tags paged two at a time."""
    token_requests = 0

    def log_message(self, *args):
        pass

    def reply(self, code, body=None, headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)
        port = self.server.server_address[1]
        if url.path == "/token":
            MockRegistry.token_requests += 1
            good = "Basic " + base64.b64encode(":".join(CREDS).encode()).decode()
            ok = self.headers.get("Authorization") == good and \
                q["scope"][0] in ("repository:proj/app:pull", "registry:catalog:*")
            return self.reply(200, {"token": "T0K"}) if ok else self.reply(401)
        if self.headers.get("Authorization") != "Bearer T0K":
            return self.reply(401, headers=[("WWW-Authenticate",
                              f'Bearer realm="http://127.0.0.1:{port}/token",service="harbor-registry"')])
        if url.path == "/v2/_catalog":                     # two repositories per page
            start = REPOS.index(q["last"][0]) + 1 if "last" in q else 0
            page = REPOS[start:start + 2]
            link = [("Link", f'</v2/_catalog?n=2&last={page[-1]}>; rel="next"')] \
                if start + 2 < len(REPOS) else []
            return self.reply(200, {"repositories": page}, link)
        if url.path == "/v2/proj/app/tags/list":
            start = TAGS.index(q["last"][0]) + 1 if "last" in q else 0
            page = TAGS[start:start + 2]
            link = [("Link", f'</v2/proj/app/tags/list?n=2&last={page[-1]}>; rel="next"')] \
                if start + 2 < len(TAGS) else []
            return self.reply(200, {"tags": page}, link)
        tag = url.path.rsplit("/", 1)[-1]
        if tag in INDEXES:
            body = {"mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [{"platform": p, "digest": f"sha256:{p['architecture']}"}
                                  for p in INDEXES[tag]]}
            ctype = body["mediaType"]
        else:
            ctype = "application/vnd.docker.distribution.manifest.v2+json"
            body = {"mediaType": ctype, "tag": tag, "config": {"size": 1000, "digest": f"sha256:cfg-{tag}"},
                    "layers": [{"size": 3_000_000_000}, {"size": 2_000_000_000}]}
        self.reply(200, body, [("Content-Type", ctype), ("Docker-Content-Digest", f"sha256:{tag}")])


@pytest.fixture
def registry():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockRegistry)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    MockRegistry.token_requests = 0
    reg = sr.V2Registry(f"127.0.0.1:{srv.server_address[1]}", insecure=True)
    reg.creds = CREDS
    yield reg
    srv.shutdown()


def test_v2_lists_every_page_with_one_token(registry):
    assert registry.tags("proj/app") == TAGS
    assert MockRegistry.token_requests == 1


def test_v2_picks_newest_versions_and_builds_full_refs(registry):
    entry = {"repo": "proj/app", "include": r"^\d+\.\d+\.\d+$", "limit": 2, "platform": "linux/amd64"}
    assert sr.list_tags_v2(entry, registry) == [
        (f"{registry.host}/proj/app:2.0.0", "proj/app", "2.0.0", "sha256:2.0.0"),
        (f"{registry.host}/proj/app:1.10.0", "proj/app", "1.10.0", "sha256:1.10.0"),
    ]


def test_v2_skips_indexes_without_our_platform(registry):
    assert registry.digest("proj/app", "multi", "linux/amd64") == "sha256:multi"
    assert registry.digest("proj/app", "armonly", "linux/amd64") is None


def test_v2_wrong_login_says_so(registry):
    registry.creds = ("robot$scanner", "wrong")
    with pytest.raises(RuntimeError, match="token request refused"):
        registry.tags("proj/app")


def test_catalog_lists_every_repository(registry):
    assert registry.catalog() == REPOS


def test_no_repositories_in_the_config_means_every_repository(registry):
    cfg = {"registry": registry.host, "include": r"^\d+\.\d+\.\d+$", "limit": 2,
           "exclude_repos": "^test/"}
    entries = sr.repositories(cfg, {registry.host: registry})
    assert entries == [{"repo": "proj/app", "include": r"^\d+\.\d+\.\d+$", "limit": 2},
                       {"repo": "proj/worker", "include": r"^\d+\.\d+\.\d+$", "limit": 2}]
    listed = sr.list_tags_v2({**entries[0], "platform": "linux/amd64"}, registry)
    assert [t[2] for t in listed] == ["2.0.0", "1.10.0"]              # the shared filter applies


def test_a_named_list_still_wins_and_docker_hub_needs_one(registry):
    named = [{"repo": "proj/app"}]
    assert sr.repositories({"registry": registry.host, "repositories": named}, {}) is named
    with pytest.raises(RuntimeError, match="name them"):
        sr.repositories({"registry": "docker.io"}, {})


def test_missing_config_says_how_to_create_it(tmp_path):
    with pytest.raises(SystemExit) as e:
        sr.main(["--config", str(tmp_path / "registries.json")])
    assert "cp registries.example.json registries.json" in str(e.value)


def test_creds_come_from_docker_login(tmp_path, monkeypatch):
    saved = base64.b64encode(b"scanner:pa:ss").decode()
    (tmp_path / "config.json").write_text(json.dumps({"auths": {"reg.sweri.local:5000": {"auth": saved}}}))
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    monkeypatch.delenv("SBOM_REGISTRY_USER", raising=False)
    assert sr.registry_creds("reg.sweri.local:5000") == ("scanner", "pa:ss")
    assert sr.registry_creds("other:5000") is None


def test_digest_references_keep_the_registry_port():
    assert sr.split_ref("reg:5000/ml/app:1.0") == ("reg:5000/ml/app", "1.0")
    assert sr.split_ref("reg:5000/ml/app") == ("reg:5000/ml/app", None)
    assert sr.digest_ref("reg:5000/ml/app:1.0", "sha256:bbb") == "reg:5000/ml/app@sha256:bbb"
    assert sr.digest_ref("ubuntu:22.04", "sha256:ccc") == "ubuntu@sha256:ccc"


def test_helpers():
    assert sorted(["1.9", "1.10", "1.2"], key=sr.version_key) == ["1.2", "1.9", "1.10"]
    assert sr.next_link('</v2/a/tags/list?last=b>; rel="next"', "https://r:5000") == \
        "https://r:5000/v2/a/tags/list?last=b"
    assert sr.next_link(None, "https://r") is None
    uri = "mongodb://sbom:hunter2@mongo.sweri.local:27017/sweri_sbom?tls=true"
    assert redact(uri) == "mongodb://sbom:***@mongo.sweri.local:27017/sweri_sbom?tls=true"
    assert redact("mongodb://localhost:27017") == "mongodb://localhost:27017"


# ---- one image end to end: download by digest, scan + ship with scan_all's code, record, remove

TRIVY = ("0.74.0", "2026-10-01T00:00:00Z", True)
ITEM = ("example/app:1.0", "example/app", "1.0", "sha256:aaa", "docker.io")


@pytest.fixture
def registry_host(tmp_path, wazuh_log, monkeypatch):
    """A scanning machine with no images, and a registry holding example/app at two digests:
    sha256:aaa (built on Debian 12.7) and sha256:bbb (rebuilt on 12.8)."""
    docker = FakeDocker()
    docker.in_registry("example/app@sha256:aaa", "sha256:id-127", F127)
    docker.in_registry("example/app@sha256:bbb", "sha256:id-128", F128)
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(sr, "REG_OUT", tmp_path / "registry")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", wazuh_log)
    monkeypatch.setattr(scan_all, "WAZUH_EPS", 0)
    return docker


def test_registry_image_gets_the_same_events_as_host_mode(db, wazuh_log, registry_host):
    assert sr.process(db, ITEM, TRIVY, "linux/amd64")["status"] == "ok"
    first = read_events(wazuh_log)
    kinds = by_kind(first)
    assert (len(kinds["component"]), len(kinds["vulnerability"])) == (8, 7)  # as host mode: no folder paths
    assert all(e["scanner_mode"] == "registry" and e["digest"] == "sha256:aaa"
               and e["cause"] == "baseline" for e in first)
    assert registry_host.pulls == ["example/app@sha256:aaa"]                # by digest, never by tag
    assert registry_host.scans == ["example/app@sha256:aaa"]
    assert registry_host.resolve("example/app@sha256:aaa") is None          # removed after the scan
    assert db.registry_scans.find_one({"image": ITEM[0]})["packages"] == 8
    assert db.scans.find_one({"image": ITEM[0]})["scanner_mode"] == "registry"

    # the tag is rebuilt (new digest): only the changes are sent, labelled like host mode's
    sr.process(db, ITEM[:3] + ("sha256:bbb", "docker.io"), TRIVY, "linux/amd64")
    kinds = by_kind(read_events(wazuh_log)[len(first):])
    assert len(kinds["component_changed"]) == 4
    assert [(e["cve_id"], e["cause"]) for e in kinds["vulnerability"]] == [("CVE-2024-2398", "image_changed")]


def test_registry_scans_work_as_the_scanners_own_user_although_trivy_writes_as_root(
        db, wazuh_log, registry_host, monkeypatch):
    RootOwned(monkeypatch, registry_host)
    assert sr.process(db, ITEM, TRIVY, "linux/amd64")["status"] == "ok"
    assert len(read_events(wazuh_log)) == BASELINE_EVENTS
    saved = json.loads((sr.REG_OUT / "example_app_1.0.json").read_text())
    assert saved["metadata"]["component"]["name"] == "example/app:1.0"


def test_failed_registry_scan_is_recorded_and_the_image_still_removed(db, wazuh_log, registry_host):
    registry_host.images["sha256:id-127"]["error"] = "FATAL boom"
    assert sr.process(db, ITEM, TRIVY, "linux/amd64")["status"] == "failed"
    record = db.registry_scans.find_one({"image": ITEM[0]})
    assert record["attempts"] == 1 and "FATAL boom" in record["error"]
    assert registry_host.removed == ["example/app@sha256:aaa"] and read_events(wazuh_log) == []


def test_an_identical_image_already_here_is_scanned_in_place_and_kept(db, wazuh_log, registry_host):
    registry_host.image("sha256:id-127", tags=["example/app:1.0"], digests=["example/app@sha256:aaa"])
    assert sr.process(db, ITEM, TRIVY, "linux/amd64")["status"] == "ok"
    assert (registry_host.pulls, registry_host.removed) == ([], [])
    assert registry_host.resolve("example/app:1.0") == "sha256:id-127"
    assert len(read_events(wazuh_log)) == BASELINE_EVENTS


def test_a_different_image_under_the_same_tag_here_is_left_alone(db, wazuh_log, registry_host):
    """A build made on this machine, tagged like the registry's image: the registry's image is
    downloaded by digest and scanned, and the tag here still points to the local build."""
    registry_host.image("sha256:built-here", tags=["example/app:1.0"], fixture=F128)
    assert sr.process(db, ITEM, TRIVY, "linux/amd64")["status"] == "ok"
    assert registry_host.pulls == ["example/app@sha256:aaa"]
    assert registry_host.resolve("example/app:1.0") == "sha256:built-here"
    assert registry_host.resolve("example/app@sha256:aaa") is None          # the download is removed
    cves = {e["cve_id"] for e in by_kind(read_events(wazuh_log))["vulnerability"]}
    assert ONLY_IN_F127 <= cves and not ONLY_IN_F128 & cves                 # the registry's image


def test_tags_that_are_the_same_image_are_scanned_once(db, wazuh_log, registry_host, monkeypatch, tmp_path):
    listed = [("example/app:latest", "example/app", "latest", "sha256:aaa"),
              ("example/app:1.0", "example/app", "1.0", "sha256:aaa"),
              ("example/app:0.9", "example/app", "0.9", "sha256:bbb")]
    monkeypatch.setattr(sr, "list_tags", lambda entry: list(listed))
    scan_all.ingest(db, "example/app:latest", F128, wazuh_log=str(tmp_path / "before.jsonl"), eps=0)
    cfg = {"repositories": [{"repo": "example/app"}]}
    assert [r["status"] for r in sr.one_pass(cfg, db)] == ["ok", "ok"]
    assert db.vuln_state.count_documents({"image": "example/app:latest"}) == 0   # old per-tag record
    assert registry_host.scans == ["example/app@sha256:aaa", "example/app@sha256:bbb"]
    assert {(e["image"], e.get("other_tags")) for e in read_events(wazuh_log)} == \
        {("example/app:1.0", "example/app:latest"), ("example/app:0.9", None)}
    latest = db.registry_scans.find_one({"image": "example/app:latest"})
    assert (latest["status"], latest["same_as"]) == ("ok", "example/app:1.0")

    # a new tag for an image already scanned is recorded as done, not scanned again
    listed.append(("example/app:stable", "example/app", "stable", "sha256:aaa"))
    assert sr.one_pass(cfg, db) == [] and len(registry_host.scans) == 2
    assert db.registry_scans.find_one({"image": "example/app:stable"})["same_as"] == "example/app:1.0"


def test_pass_skips_done_and_abandoned_images_and_prepares_trivy_only_when_needed(db, monkeypatch):
    listed = [(f"r/a:{n}", "r/a", str(n), f"sha256:{n}") for n in (1, 2, 3)]
    monkeypatch.setattr(sr, "list_tags", lambda entry: listed)
    db.registry_scans.insert_many([{"image": "r/a:1", "digest": "sha256:1", "status": "ok"},
                                   {"image": "r/a:2", "digest": "sha256:2", "status": "failed",
                                    "attempts": sr.MAX_ATTEMPTS, "timeout": scan_all.SCAN_TIMEOUT}])
    prepared, processed = [], []
    monkeypatch.setattr(scan_all, "prepare_trivy", lambda: prepared.append(1) or TRIVY)
    monkeypatch.setattr(sr, "process", lambda db, item, trivy, platform, **kw:
                        processed.append(item[0]) or {"image": item[0], "status": "ok"})
    cfg = {"repositories": [{"repo": "r/a"}]}
    results = sr.one_pass(cfg, db)
    assert (processed, prepared) == (["r/a:3"], [1])
    assert {"image": "r/a:2", "status": "abandoned"} in results
    db.registry_scans.insert_one({"image": "r/a:3", "digest": "sha256:3", "status": "ok"})
    sr.one_pass(cfg, db)
    assert prepared == [1]                                                  # nothing new, no DB download


def test_old_format_state_is_set_aside_not_crashed_on(monkeypatch, tmp_path):
    """A MongoDB that ran the September version: state keyed on purl, no host/identity.
    Building the new unique index on it used to fail with a duplicate key error."""
    db = __import__("mongomock").MongoClient().db
    old = {"image": "python:3.11-slim", "cve_id": "CVE-2007-5686", "purl": "pkg:deb/debian/login@1"}
    db.vuln_state.insert_many([dict(old), {**old, "purl": "pkg:deb/debian/passwd@1"}])
    monkeypatch.setattr(sr, "get_db", lambda: db)
    monkeypatch.setattr(sr, "OUT_DIR", tmp_path)
    monkeypatch.setattr(sr, "REG_OUT", tmp_path / "registry")
    monkeypatch.setattr(scan_all, "check_wazuh_log", lambda path: None)
    monkeypatch.setattr(sr, "one_pass", lambda cfg, db, **kw: [])
    cfg = tmp_path / "reg.json"
    cfg.write_text(json.dumps({"repositories": []}))

    assert sr.main(["--config", str(cfg), "--dry-run"]) == 0
    assert "vuln_state_legacy" not in db.list_collection_names()          # dry run: untouched
    assert sr.main(["--config", str(cfg)]) == 0
    assert db.vuln_state_legacy.count_documents({}) == 2                  # kept, not deleted
    assert db.vuln_state.count_documents({}) == 0


def test_registry_run_summary_reports_an_unreadable_registry(monkeypatch, tmp_path, wazuh_log):
    """An expired login must show up in Wazuh as an error, not as a quiet hour."""
    db = __import__("mongomock").MongoClient().db
    cfg = tmp_path / "reg.json"
    cfg.write_text(json.dumps({"registry": "reg.example:5000"}))
    monkeypatch.setattr(sr, "get_db", lambda: db)
    monkeypatch.setattr(sr, "OUT_DIR", tmp_path)
    monkeypatch.setattr(sr, "REG_OUT", tmp_path / "registry")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", wazuh_log)

    def refuse(cfg, clients):
        raise RuntimeError("reg.example:5000 rejected the scanner's login")
    monkeypatch.setattr(sr, "repositories", refuse)
    assert sr.main(["--config", str(cfg)]) == 1
    [summary] = read_events(wazuh_log)
    assert (summary["sbom_event"], summary["scanner_mode"], summary["run_status"]) == \
        ("scan_run", "registry", "error")
    assert "rejected the scanner's login" in summary["errors"]

    assert sr.main(["--config", str(cfg), "--dry-run"]) == 1          # a dry run sends nothing
    assert len(read_events(wazuh_log)) == 1


def test_registry_run_summary_counts_scans_and_failures(monkeypatch, tmp_path, wazuh_log):
    db = __import__("mongomock").MongoClient().db
    cfg = tmp_path / "reg.json"
    cfg.write_text(json.dumps({"repositories": []}))
    monkeypatch.setattr(sr, "get_db", lambda: db)
    monkeypatch.setattr(sr, "OUT_DIR", tmp_path)
    monkeypatch.setattr(sr, "REG_OUT", tmp_path / "registry")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", wazuh_log)
    monkeypatch.setattr(sr, "one_pass", lambda cfg, db, **kw: [
        {"image": "r/a:1", "status": "ok"}, {"image": "r/a:2", "status": "failed", "error": "pull failed: x"}])
    assert sr.main(["--config", str(cfg)]) == 1
    [summary] = read_events(wazuh_log)
    assert (summary["run_status"], summary["scanned"], summary["failed"], summary["skipped"]) == \
        ("failed", 1, 1, 0)
    assert summary["errors"] == "r/a:2: pull failed: x"


def test_mongodb_down_is_reported_before_stopping(monkeypatch, tmp_path, wazuh_log):
    cfg = tmp_path / "reg.json"
    cfg.write_text(json.dumps({"repositories": []}))
    monkeypatch.setattr(sr, "OUT_DIR", tmp_path)
    monkeypatch.setattr(sr, "REG_OUT", tmp_path / "registry")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", wazuh_log)

    def down():
        raise SystemExit("Cannot reach MongoDB at mongodb://db:27017")
    monkeypatch.setattr(sr, "get_db", down)
    with pytest.raises(SystemExit):
        sr.main(["--config", str(cfg)])
    [summary] = read_events(wazuh_log)
    assert summary["run_status"] == "error" and "Cannot reach MongoDB" in summary["errors"]


def test_size_and_config_digest_are_read_from_the_manifest_for_our_platform(registry):
    assert registry.size("proj/app", "2.0.0", "linux/amd64") == 5_000_001_000
    assert registry.size("proj/app", "multi", "linux/amd64") == 5_000_001_000  # via the amd64 manifest
    assert registry.size("proj/app", "armonly", "linux/amd64") is None
    assert registry.config_digest("proj/app", "2.0.0", "linux/amd64") == "sha256:cfg-2.0.0"
    assert registry.config_digest("proj/app", "multi", "linux/amd64") == "sha256:cfg-sha256:amd64"
    assert registry.config_digest("proj/app", "armonly", "linux/amd64") is None


def test_space_check(monkeypatch, tmp_path):
    usage = lambda free: (lambda root: SimpleNamespace(free=free * 1e9))  # noqa: E731
    monkeypatch.setattr(sr, "MIN_FREE_GB", 10)
    monkeypatch.setattr(sr.shutil, "disk_usage", usage(40))
    assert sr.space_problem(5e9, str(tmp_path)) is None                   # needs 5*5 + 10 = 35
    monkeypatch.setattr(sr.shutil, "disk_usage", usage(20))
    msg = sr.space_problem(5e9, str(tmp_path))
    assert "20.0 GB free" in msg and "35.0 GB needed" in msg
    assert sr.space_problem(None, str(tmp_path)) is None                   # unknown size: minimum only
    assert sr.space_problem(5e9, None) is None                             # Docker's folder unknown


def test_full_disk_skips_the_pull_without_using_an_attempt(db, wazuh_log, registry_host, monkeypatch):
    monkeypatch.setattr(sr, "space_problem", lambda size, root: "not enough disk space")
    r = sr.process(db, ITEM, TRIVY, "linux/amd64", size=9e9, root="/var/lib/docker")
    assert (r["status"], r["error"]) == ("failed", "not enough disk space")
    assert registry_host.pulls == []                                       # never downloaded
    record = db.registry_scans.find_one({"image": ITEM[0]})
    assert record["attempts"] == 0 and read_events(wazuh_log) == []


def _registry_main_env(monkeypatch, tmp_path, wazuh_log, cfg, db=None):
    path = tmp_path / "reg.json"
    path.write_text(json.dumps(cfg))
    monkeypatch.setattr(sr, "get_db", lambda: mongomock.MongoClient().db if db is None else db)
    monkeypatch.setattr(sr, "OUT_DIR", tmp_path)
    monkeypatch.setattr(scan_all, "OUT_DIR", tmp_path)
    monkeypatch.setattr(sr, "REG_OUT", tmp_path / "registry")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", wazuh_log)
    monkeypatch.setattr(scan_all, "WAZUH_EPS", 0)
    return str(path)


def _build_server(monkeypatch, tmp_path, wazuh_log, db):
    """A build server that pushes to its registry.
    Here: acr/app:1.0 (also tagged latest, and pushed), acr/app:0.9 rebuilt here since it
    was pushed (so it differs from the registry's 0.9), and acr/tool:dev, never pushed.
    In the registry: acr/app latest and 1.0 (the image here), 0.9 (the older build), 0.8."""
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log, {"repositories": [{"repo": "acr/app"}]}, db)
    docker = FakeDocker()
    docker.image("sha256:app-1.0", tags=["acr/app:1.0", "acr/app:latest"], digests=["acr/app@sha256:x"])
    docker.image("sha256:app-0.9-rebuilt", tags=["acr/app:0.9"], fixture=F128)
    docker.image("sha256:tool", tags=["acr/tool:dev"])
    docker.in_registry("acr/app@sha256:z", "sha256:app-0.9", F128)
    docker.in_registry("acr/app@sha256:y", "sha256:app-0.8", F127)
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(sr, "list_tags", lambda entry: [
        ("acr/app:latest", "acr/app", "latest", "sha256:x"), ("acr/app:1.0", "acr/app", "1.0", "sha256:x"),
        ("acr/app:0.9", "acr/app", "0.9", "sha256:z"), ("acr/app:0.8", "acr/app", "0.8", "sha256:y")])
    return cfg, docker


def test_local_scans_this_machine_first_then_only_what_is_missing(monkeypatch, tmp_path, wazuh_log, capsys):
    db = mongomock.MongoClient().db
    cfg, docker = _build_server(monkeypatch, tmp_path, wazuh_log, db)
    assert sr.main(["--config", cfg, "--local"]) == 0
    # each image here once, by its ID and without downloading; then, by digest, the one image
    # that only the registry has
    assert docker.scans == ["sha256:app-0.9-rebuilt", "sha256:app-1.0", "sha256:tool", "acr/app@sha256:y"]
    assert docker.pulls == docker.removed == ["acr/app@sha256:y"]
    assert docker.resolve("acr/app:0.9") == "sha256:app-0.9-rebuilt"          # never replaced
    done = {d["image"]: d for d in db.registry_scans.find()}
    assert done["acr/app:latest"]["same_as"] == done["acr/app:1.0"]["same_as"] == "acr/app:1.0"
    assert done["acr/app:0.8"]["status"] == "ok" and "acr/app:0.9" not in done
    assert "acr/app:0.9: skipped, this machine has a different image under this name" in \
        capsys.readouterr().out
    summary = read_events(wazuh_log)[-1]
    assert (summary["scanner_mode"], summary["run_status"], summary["scanned"], summary["failed"],
            summary["skipped"]) == ("local+registry", "ok", 4, 0, 1)

    docker.scans.clear()                # next run: this machine's images again; the registry is done
    assert sr.main(["--config", cfg, "--local"]) == 0
    assert docker.scans == ["sha256:app-0.9-rebuilt", "sha256:app-1.0", "sha256:tool"]
    assert docker.pulls == ["acr/app@sha256:y"]


def test_local_counts_an_image_known_here_only_by_a_leftover_digest(monkeypatch, tmp_path, wazuh_log):
    """A tag that moved to a newer build leaves the old image with the registry digest but no
    tag in that repository. It is still the registry's image, scanned here under its other name."""
    db = mongomock.MongoClient().db
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log, {"repositories": [{"repo": "acr/fox"}]}, db)
    docker = FakeDocker()
    docker.image("sha256:x", tags=["fox-desktop:optimized"], digests=["acr/fox@sha256:d1"])
    docker.image("sha256:y", tags=["acr/fox:latest"], digests=["acr/fox@sha256:d2"], fixture=F128)
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(sr, "list_tags", lambda entry: [("acr/fox:1.0", "acr/fox", "1.0", "sha256:d1"),
                                                        ("acr/fox:latest", "acr/fox", "latest", "sha256:d2")])
    assert sr.main(["--config", cfg, "--local"]) == 0
    assert docker.scans == ["sha256:y", "sha256:x"] and docker.pulls == []
    assert {e["image"] for e in findings(wazuh_log)} == {"acr/fox:latest", "fox-desktop:optimized"}
    assert db.registry_scans.find_one({"image": "acr/fox:1.0"})["same_as"] == "fox-desktop:optimized"


def test_local_recognises_an_image_here_by_its_config_when_docker_forgot_the_digest(
        monkeypatch, tmp_path, wazuh_log):
    """Pushed, then its registry tag removed here: Docker no longer knows the registry digest,
    but the registry's config digest is the image ID, so it isn't downloaded and reported again."""
    db = mongomock.MongoClient().db
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log,
                             {"registry": "acr.example.io", "repositories": [{"repo": "fox"}]}, db)
    docker = FakeDocker()
    docker.image("sha256:x", tags=["fox-desktop:optimized"])
    docker.in_registry("acr.example.io/fox@sha256:d1", "sha256:x")
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(sr, "V2Registry", FakeRegistry("acr.example.io", {"fox": {"1.0": ("sha256:d1", "sha256:x")}}))
    assert sr.main(["--config", cfg, "--local"]) == 0
    assert docker.scans == ["sha256:x"] and docker.pulls == []
    assert db.registry_scans.find_one({"image": "acr.example.io/fox:1.0"})["same_as"] == "fox-desktop:optimized"


def test_local_recognises_an_image_here_after_downloading_it_when_nothing_else_can(
        monkeypatch, tmp_path, wazuh_log):
    """As above, from a registry that can't say what the image's config is beforehand (Docker
    Hub): downloading it only confirms layers already here, and the image ID then shows it's
    an image already scanned. It is recorded as that, not reported again, and only the
    digest reference the download added is removed."""
    db = mongomock.MongoClient().db
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log, {"repositories": [{"repo": "acr/fox"}]}, db)
    docker = FakeDocker()
    docker.image("sha256:x", tags=["fox-desktop:optimized"])
    docker.in_registry("acr/fox@sha256:d1", "sha256:x")
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(sr, "list_tags", lambda entry: [("acr/fox:1.0", "acr/fox", "1.0", "sha256:d1")])
    assert sr.main(["--config", cfg, "--local"]) == 0
    assert docker.scans == ["sha256:x"] and docker.pulls == docker.removed == ["acr/fox@sha256:d1"]
    assert docker.resolve("fox-desktop:optimized") == "sha256:x"           # still here
    assert {e["image"] for e in findings(wazuh_log)} == {"fox-desktop:optimized"}
    assert db.registry_scans.find_one({"image": "acr/fox:1.0"})["same_as"] == "fox-desktop:optimized"


def test_a_docker_that_doesnt_answer_never_leads_to_removing_an_image(db, wazuh_log, tmp_path, monkeypatch):
    docker = FakeDocker()
    docker.image("sha256:base", digests=["acr/base@sha256:bbb"])          # here only by digest
    slow = {"inspects": 1}

    def flaky(cmd, **kwargs):
        if cmd[:3] == ["docker", "image", "inspect"] and slow["inspects"]:
            slow["inspects"] -= 1
            raise subprocess.TimeoutExpired(cmd, 60)
        return docker(cmd, **kwargs)
    monkeypatch.setattr(scan_all.subprocess, "run", flaky)
    monkeypatch.setattr(sr, "REG_OUT", tmp_path / "registry")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", wazuh_log)
    item = ("acr/base:1.0", "acr/base", "1.0", "sha256:bbb", "acr.example.io")
    r = sr.process(db, item, TRIVY, "linux/amd64")
    assert r["status"] == "failed" and "couldn't ask Docker" in r["error"]
    assert (docker.pulls, docker.scans, docker.removed) == ([], [], [])     # left alone this pass
    assert db.registry_scans.find_one({"image": "acr/base:1.0"})["attempts"] == 0

    # downloaded and scanned, but Docker stops answering before the clean-up: left in place
    docker.in_registry("acr/new@sha256:ccc", "sha256:new")
    slow["inspects"] = 0
    real = docker.trivy

    def scan_then_stall(cmd):
        result = real(cmd)
        slow["inspects"] = 99
        return result
    docker.trivy = scan_then_stall
    item = ("acr/new:1.0", "acr/new", "1.0", "sha256:ccc", "acr.example.io")
    r = sr.process(db, item, TRIVY, "linux/amd64")
    assert r["status"] == "ok" and docker.pulls == ["acr/new@sha256:ccc"] and docker.removed == []
    assert r["warning"].startswith("left acr/new@sha256:ccc on this machine: Docker didn't answer")
    assert r["warning"].endswith("Remove it with: docker rmi acr/new@sha256:ccc")


def test_docker_gets_a_few_chances_to_answer_before_a_download_is_left(monkeypatch):
    docker = FakeDocker()
    docker.in_registry("acr/new@sha256:ccc", "sha256:new")
    docker(["docker", "pull", "--platform", "linux/amd64", "acr/new@sha256:ccc"])
    stalls = {"left": 1}

    def flaky(cmd, **kwargs):
        if cmd[:3] == ["docker", "image", "inspect"] and stalls["left"]:
            stalls["left"] -= 1
            raise subprocess.TimeoutExpired(cmd, 60)
        return docker(cmd, **kwargs)
    monkeypatch.setattr(scan_all.subprocess, "run", flaky)
    assert sr.remove("acr/new@sha256:ccc") is None and docker.removed == ["acr/new@sha256:ccc"]


def test_a_download_left_behind_is_named_in_the_run_summary(monkeypatch, tmp_path, wazuh_log):
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log, {"repositories": [{"repo": "acr/new"}]})
    docker = FakeDocker()
    docker.in_registry("acr/new@sha256:ccc", "sha256:new")
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(sr, "list_tags", lambda entry: [("acr/new:1.0", "acr/new", "1.0", "sha256:ccc")])
    monkeypatch.setattr(sr, "remove", lambda ref: f"left {ref} on this machine: in use")
    assert sr.main(["--config", cfg]) == 0
    summary = read_events(wazuh_log)[-1]
    assert (summary["run_status"], summary["scanned"], summary["failed"]) == ("failed", 1, 0)  # rule 100209
    assert summary["errors"] == "acr/new:1.0: left acr/new@sha256:ccc on this machine: in use"


def test_an_image_given_up_on_is_counted_and_a_new_timeout_or_retry_failed_tries_it_again(
        monkeypatch, tmp_path, wazuh_log, capsys):
    db = mongomock.MongoClient().db
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log, {"repositories": [{"repo": "acr/big"}]}, db)
    docker = FakeDocker()
    docker.in_registry("acr/big@sha256:big", "sha256:big",
                       error="FATAL image scan error: context deadline exceeded")
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(sr, "list_tags", lambda entry: [         # one image, counted once
        (f"acr/big:{tag}", "acr/big", tag, "sha256:big") for tag in ("1.0", "latest")])
    for _ in range(sr.MAX_ATTEMPTS):
        assert sr.main(["--config", cfg]) == 1
    assert read_events(wazuh_log)[-1]["errors"].endswith("context deadline exceeded (gave up after 3 tries)")
    assert sr.main(["--config", cfg]) == 0                                  # given up on: not tried
    summary = read_events(wazuh_log)[-1]
    assert (summary["run_status"], summary["abandoned"], len(docker.pulls)) == ("ok", 1, 3)

    monkeypatch.setattr(scan_all, "SCAN_TIMEOUT", "2h")                     # as the README advises
    for _ in range(sr.MAX_ATTEMPTS + 1):                                    # three new tries, then not
        sr.main(["--config", cfg])
    assert (len(docker.pulls), read_events(wazuh_log)[-1]["abandoned"]) == (6, 1)

    docker.images["sha256:big"]["error"] = None                             # whatever it was, fixed
    assert sr.main(["--config", cfg]) == 0 and len(docker.pulls) == 6       # still given up on
    capsys.readouterr()
    assert sr.main(["--config", cfg, "--retry-failed", "--dry-run"]) == 0  # shows it would try again
    assert "would scan acr/big:1.0" in capsys.readouterr().out and len(docker.pulls) == 6
    assert sr.main(["--config", cfg, "--retry-failed"]) == 0 and len(docker.pulls) == 7
    summary = read_events(wazuh_log)[-1]
    assert (summary["scanned"], summary["abandoned"]) == (1, 0)


def test_an_image_given_up_on_that_is_now_on_this_machine_counts_as_scanned(monkeypatch, tmp_path, wazuh_log):
    db = mongomock.MongoClient().db
    db.registry_scans.insert_one({"image": "acr/big:1.0", "digest": "sha256:big", "status": "failed",
                                  "attempts": sr.MAX_ATTEMPTS, "timeout": scan_all.SCAN_TIMEOUT})
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log, {"repositories": [{"repo": "acr/big"}]}, db)
    docker = FakeDocker()
    docker.image("sha256:big", tags=["acr/big:1.0"], digests=["acr/big@sha256:big"])
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(sr, "list_tags", lambda entry: [("acr/big:1.0", "acr/big", "1.0", "sha256:big")])
    assert sr.main(["--config", cfg, "--local"]) == 0
    summary = read_events(wazuh_log)[-1]
    assert (summary["scanned"], summary["abandoned"]) == (1, 0)
    assert db.registry_scans.find_one({"image": "acr/big:1.0"})["status"] == "ok"


def test_tags_sharing_a_digest_get_three_tries_between_them(db, wazuh_log, tmp_path, monkeypatch):
    docker = FakeDocker()
    docker.in_registry("example/app@sha256:aaa", "sha256:id", F127,
                       error="FATAL image scan error: context deadline exceeded")
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(sr, "REG_OUT", tmp_path / "registry")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", wazuh_log)
    monkeypatch.setattr(sr, "list_tags", lambda entry: [
        (f"example/app:{tag}", "example/app", tag, "sha256:aaa") for tag in ("1.0", "latest", "stable")])
    for _ in range(6):
        sr.one_pass({"repositories": [{"repo": "example/app"}]}, db)
    assert len(docker.pulls) == sr.MAX_ATTEMPTS


def test_a_local_run_that_cannot_start_is_reported_as_one(monkeypatch, tmp_path, wazuh_log):
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log, {"repositories": []})
    monkeypatch.setattr(scan_all, "local_images",
                        lambda: (_ for _ in ()).throw(SystemExit("'docker images' failed: daemon down")))
    with pytest.raises(SystemExit):
        sr.main(["--config", cfg, "--local"])
    [summary] = read_events(wazuh_log)
    assert (summary["scanner_mode"], summary["run_status"]) == ("local+registry", "error")


def test_an_image_that_failed_here_is_not_tried_again_from_the_registry(monkeypatch, tmp_path, wazuh_log):
    db = mongomock.MongoClient().db
    cfg, docker = _build_server(monkeypatch, tmp_path, wazuh_log, db)
    docker.images["sha256:app-1.0"]["error"] = "FATAL image scan error: context deadline exceeded"
    listed = sr.list_tags(None) + [("acr/app:1.0-final", "acr/app", "1.0-final", "sha256:x")]
    monkeypatch.setattr(sr, "list_tags", lambda entry: listed)
    assert sr.main(["--config", cfg, "--local"]) == 1
    assert docker.scans == ["sha256:app-0.9-rebuilt", "sha256:tool", "acr/app@sha256:y"]
    summary = read_events(wazuh_log)[-1]
    assert (summary["run_status"], summary["scanned"], summary["failed"]) == ("failed", 3, 1)
    assert summary["errors"] == "acr/app:1.0: FATAL image scan error: context deadline exceeded"


def test_local_dry_run_lists_both_and_changes_nothing(monkeypatch, tmp_path, wazuh_log, capsys):
    db = mongomock.MongoClient().db
    cfg, docker = _build_server(monkeypatch, tmp_path, wazuh_log, db)
    assert sr.main(["--config", cfg, "--local", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would scan acr/app:1.0  (also tagged acr/app:latest)" in out
    assert "would scan acr/tool:dev" in out and "would scan acr/app:0.8  sha256:y" in out
    assert "would scan acr/app:latest" not in out
    assert (docker.scans, docker.pulls) == ([], [])
    assert read_events(wazuh_log) == [] and db.registry_scans.count_documents({}) == 0


def test_a_crash_mid_run_is_still_reported(monkeypatch, tmp_path, wazuh_log):
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log, {"repositories": []})

    def crash(cfg, db, **kw):
        raise ConnectionError("MongoDB went away")
    monkeypatch.setattr(sr, "one_pass", crash)
    with pytest.raises(ConnectionError):
        sr.main(["--config", cfg])
    [summary] = read_events(wazuh_log)
    assert summary["run_status"] == "error" and "MongoDB went away" in summary["errors"]


def test_one_unreadable_repository_is_a_failure_not_an_outage(monkeypatch, tmp_path, wazuh_log):
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log,
                             {"repositories": [{"repo": "a"}, {"repo": "b"}]})

    def tags(entry):
        if entry["repo"] == "b":
            raise RuntimeError("HTTP 401")
        return []
    monkeypatch.setattr(sr, "list_tags", tags)
    assert sr.main(["--config", cfg]) == 1
    [summary] = read_events(wazuh_log)
    assert (summary["run_status"], summary["failed"]) == ("failed", 1)
    assert "b: HTTP 401" in summary["errors"]


def test_another_scan_running_and_dry_runs_send_no_summary(monkeypatch, tmp_path, wazuh_log):
    cfg = _registry_main_env(monkeypatch, tmp_path, wazuh_log, {"repositories": []})

    def busy(out_dir):
        raise SystemExit(scan_all.LOCKED)
    monkeypatch.setattr(scan_all, "acquire_lock", busy)
    with pytest.raises(SystemExit):
        sr.main(["--config", cfg])
    monkeypatch.setattr(sr, "one_pass", lambda cfg, db, **kw: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        sr.main(["--config", cfg, "--dry-run"])
    assert read_events(wazuh_log) == []


def test_long_error_lists_are_cut_to_fit_a_wazuh_alert(wazuh_log):
    scan_all.report_run("registry", 0, 5, [f"img{i}: " + "x" * 300 for i in range(5)], path=wazuh_log)
    [summary] = read_events(wazuh_log)
    assert len(summary["errors"]) <= scan_all.ERRORS_MAX and summary["errors"].endswith("(more in log)")
    assert summary["run_status"] == "error"                       # nothing scanned at all
