"""Registry-mode helpers and the v2 registry client, against a local mock registry."""
import base64
import http.server
import json
import os
import shutil
import threading
import urllib.parse
from types import SimpleNamespace

import pytest

import scan_all
import scan_registry as sr
from helpers import F127, F128, by_kind, read_events
from sbom_common import redact

TAGS = ["1.9.0", "1.10.0", "1.10.0-rc1", "2.0.0", "latest"]
CREDS = ("robot$scanner", "tok3n")
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
            ok = self.headers.get("Authorization") == good and q["scope"] == ["repository:proj/app:pull"]
            return self.reply(200, {"token": "T0K"}) if ok else self.reply(401)
        if self.headers.get("Authorization") != "Bearer T0K":
            return self.reply(401, headers=[("WWW-Authenticate",
                              f'Bearer realm="http://127.0.0.1:{port}/token",service="harbor-registry"')])
        if url.path == "/v2/proj/app/tags/list":
            start = TAGS.index(q["last"][0]) + 1 if "last" in q else 0
            page = TAGS[start:start + 2]
            link = [("Link", f'</v2/proj/app/tags/list?n=2&last={page[-1]}>; rel="next"')] \
                if start + 2 < len(TAGS) else []
            return self.reply(200, {"tags": page}, link)
        tag = url.path.rsplit("/", 1)[-1]
        if tag in INDEXES:
            body = {"mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [{"platform": p} for p in INDEXES[tag]]}
            ctype = body["mediaType"]
        else:
            ctype = "application/vnd.docker.distribution.manifest.v2+json"
            body = {"mediaType": ctype, "tag": tag}
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


def test_creds_come_from_docker_login(tmp_path, monkeypatch):
    saved = base64.b64encode(b"scanner:pa:ss").decode()
    (tmp_path / "config.json").write_text(json.dumps({"auths": {"reg.sweri.local:5000": {"auth": saved}}}))
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    monkeypatch.delenv("SBOM_REGISTRY_USER", raising=False)
    assert sr.registry_creds("reg.sweri.local:5000") == ("scanner", "pa:ss")
    assert sr.registry_creds("other:5000") is None


def test_local_digest_prefers_this_repo(monkeypatch):
    out = "other.io/x@sha256:aaa\nreg:5000/ml/app@sha256:bbb\n"
    monkeypatch.setattr(sr, "run", lambda cmd, timeout: SimpleNamespace(stdout=out))
    assert sr.local_digest("reg:5000/ml/app:1.0") == "sha256:bbb"


def test_helpers():
    assert sorted(["1.9", "1.10", "1.2"], key=sr.version_key) == ["1.2", "1.9", "1.10"]
    assert sr.next_link('</v2/a/tags/list?last=b>; rel="next"', "https://r:5000") == \
        "https://r:5000/v2/a/tags/list?last=b"
    assert sr.next_link(None, "https://r") is None
    uri = "mongodb://sbom:hunter2@mongo.sweri.local:27017/sweri_sbom?tls=true"
    assert redact(uri) == "mongodb://sbom:***@mongo.sweri.local:27017/sweri_sbom?tls=true"
    assert redact("mongodb://localhost:27017") == "mongodb://localhost:27017"


# ---- one image end to end: pull, scan + ship with scan_all's code, record, remove

TRIVY = ("0.74.0", "2026-10-01T00:00:00Z", True)
ITEM = ("example/app:1.0", "example/app", "1.0", "sha256:aaa", "docker.io")


class FakeDocker:
    """docker pull / image inspect / rmi: the image exists only between pull and rmi."""

    def __init__(self, digest):
        self.digest, self.present = digest, False

    def __call__(self, cmd, timeout):
        if cmd[1] in ("pull", "rmi"):
            self.present = cmd[1] == "pull"
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        out = f"example/app@{self.digest}\n" if "--format" in cmd else ""
        return SimpleNamespace(returncode=0 if self.present else 1, stdout=out, stderr="")


def fake_trivy(fixture):
    """Trivy run that writes the given CycloneDX fixture where scan_image expects it."""
    def run(cmd, **kwargs):
        out_dir = next(v[:-len(":/out")] for v in cmd if v.endswith(":/out"))
        shutil.copy(fixture, os.path.join(out_dir, os.path.basename(cmd[cmd.index("--output") + 1])))
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


@pytest.fixture
def registry_host(tmp_path, wazuh_log, monkeypatch):
    docker = FakeDocker("sha256:aaa")
    monkeypatch.setattr(sr, "run", docker)
    monkeypatch.setattr(sr, "REG_OUT", tmp_path / "registry")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", wazuh_log)
    monkeypatch.setattr(scan_all, "WAZUH_EPS", 0)
    return docker


def test_registry_image_gets_the_same_events_as_host_mode(db, wazuh_log, registry_host, monkeypatch):
    monkeypatch.setattr(scan_all.subprocess, "run", fake_trivy(F127))
    assert sr.process(db, ITEM, TRIVY, "linux/amd64")["status"] == "ok"
    first = read_events(wazuh_log)
    kinds = by_kind(first)
    assert (len(kinds["component"]), len(kinds["vulnerability"])) == (8, 7)  # as host mode: no folder paths
    assert all(e["scanner_mode"] == "registry" and e["digest"] == "sha256:aaa"
               and e["cause"] == "baseline" for e in first)
    assert not registry_host.present                                        # removed after the scan
    assert db.registry_scans.find_one({"image": ITEM[0]})["packages"] == 8
    assert db.scans.find_one({"image": ITEM[0]})["scanner_mode"] == "registry"

    # the tag is rebuilt (new digest): only the changes are sent, labelled like host mode's
    registry_host.digest = "sha256:bbb"
    monkeypatch.setattr(scan_all.subprocess, "run", fake_trivy(F128))
    sr.process(db, ITEM[:3] + ("sha256:bbb", "docker.io"), TRIVY, "linux/amd64")
    kinds = by_kind(read_events(wazuh_log)[len(first):])
    assert len(kinds["component_changed"]) == 4
    assert [(e["cve_id"], e["cause"]) for e in kinds["vulnerability"]] == [("CVE-2024-2398", "image_changed")]


def test_failed_registry_scan_is_recorded_and_the_image_still_removed(db, wazuh_log, registry_host, monkeypatch):
    monkeypatch.setattr(scan_all.subprocess, "run",
                        lambda cmd, **k: SimpleNamespace(returncode=1, stdout="", stderr="FATAL boom"))
    assert sr.process(db, ITEM, TRIVY, "linux/amd64")["status"] == "failed"
    record = db.registry_scans.find_one({"image": ITEM[0]})
    assert record["attempts"] == 1 and "FATAL boom" in record["error"]
    assert not registry_host.present and read_events(wazuh_log) == []


def test_pass_skips_done_and_abandoned_images_and_prepares_trivy_only_when_needed(db, monkeypatch):
    listed = [(f"r/a:{n}", "r/a", str(n), f"sha256:{n}") for n in (1, 2, 3)]
    monkeypatch.setattr(sr, "list_tags", lambda entry: listed)
    db.registry_scans.insert_many([{"image": "r/a:1", "digest": "sha256:1", "status": "ok"},
                                   {"image": "r/a:2", "digest": "sha256:2", "status": "failed",
                                    "attempts": sr.MAX_ATTEMPTS}])
    prepared, processed = [], []
    monkeypatch.setattr(scan_all, "prepare_trivy", lambda: prepared.append(1) or TRIVY)
    monkeypatch.setattr(sr, "process", lambda db, item, trivy, platform:
                        processed.append(item[0]) or {"status": "ok"})
    cfg = {"repositories": [{"repo": "r/a"}]}
    sr.one_pass(cfg, db)
    assert (processed, prepared) == (["r/a:3"], [1])
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
    monkeypatch.setattr(sr, "one_pass", lambda cfg, db, dry_run=False: [])
    cfg = tmp_path / "reg.json"
    cfg.write_text(json.dumps({"repositories": []}))

    assert sr.main(["--config", str(cfg), "--dry-run"]) == 0
    assert "vuln_state_legacy" not in db.list_collection_names()          # dry run: untouched
    assert sr.main(["--config", str(cfg)]) == 0
    assert db.vuln_state_legacy.count_documents({}) == 2                  # kept, not deleted
    assert db.vuln_state.count_documents({}) == 0
