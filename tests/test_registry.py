"""Registry-mode helpers and the v2 registry client, against a local mock registry."""
import base64
import http.server
import json
import threading
import urllib.parse
from types import SimpleNamespace

import pytest

import scan_registry as sr
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
    assert redact(uri) == sr.redact(uri) == "mongodb://sbom:***@mongo.sweri.local:27017/sweri_sbom?tls=true"
    assert redact("mongodb://localhost:27017") == "mongodb://localhost:27017"
