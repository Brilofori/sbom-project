#!/usr/bin/env python3
"""
scan_registry.py - registry mode for the SWERI SBOM pipeline.

Instead of scanning the images on this host, this watches container registries.
Each pass it:

  1. lists the tags in every repository named in registries.json
  2. skips any image (tag + digest) that has already been scanned
  3. pulls one image, then scans it and ships the changes to Wazuh exactly as
     scan_all.py does (same Trivy, parsing, change tracking and events), then
     removes the image from disk
  4. moves on to the next image

Each image is scanned once. If a tag is later rebuilt (its digest changes) it is
scanned again, and the Wazuh events show what changed. Only one image is on disk
at a time, which is what makes this workable for 10-30GB images.

Registries: Docker Hub (via its own API) and any registry that speaks the Docker
Registry v2 API - Harbor, GitLab, Nexus, Artifactory, plain registry:2. Private
registries use the login saved by `docker login <host>`, or
SBOM_REGISTRY_USER / SBOM_REGISTRY_PASSWORD.

Usage:
  python3 scan_registry.py              # one pass (use with the hourly timer)
  python3 scan_registry.py --dry-run    # list what would be scanned, pull nothing
  python3 scan_registry.py --config other.json
"""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import scan_all
from sbom_common import OUT_DIR, get_db

REG_OUT = OUT_DIR / "registry"   # latest CycloneDX file per registry image
MAX_ATTEMPTS = 3                 # give up on an image after this many failed passes
PULL_TIMEOUT = 3600              # seconds
UA = {"User-Agent": "sweri-sbom-scanner"}


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------- Docker Hub

def hub_get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
        return json.load(r)


def list_tags(entry):
    """
    Return [(image_ref, repo, tag, digest)] for one repository in the config,
    newest first, filtered by include/exclude and capped at `limit`.
    Uses the Docker Hub API, so nothing is pulled at this stage.
    Other registries go through list_tags_v2().
    """
    repo = entry["repo"]
    if "/" not in repo:
        repo = f"library/{repo}"                    # official images live under library/
    include = re.compile(entry.get("include", ".*"))
    exclude = re.compile(entry["exclude"]) if entry.get("exclude") else None
    limit = int(entry.get("limit", 5))
    os_name, arch = entry.get("platform", "linux/amd64").split("/")[:2]

    url = (f"https://hub.docker.com/v2/repositories/{repo}/tags"
           f"?page_size=100&ordering=last_updated")
    found, pages = [], 0
    while url and len(found) < limit and pages < 10:
        data = hub_get(url)
        pages += 1
        for t in data.get("results", []):
            name = t.get("name", "")
            if not include.search(name) or (exclude and exclude.search(name)):
                continue
            # only take tags that actually have an image for our platform
            if not any(i.get("os") == os_name and i.get("architecture") == arch
                       for i in t.get("images", [])):
                continue
            digest = t.get("digest")
            if not digest:
                continue
            short = repo[len("library/"):] if repo.startswith("library/") else repo
            found.append((f"{short}:{name}", short, name, digest))
            if len(found) >= limit:
                break
        url = data.get("next")
    return found


# ---------------------------------------------------------------- registry v2 (Harbor, GitLab, registry:2, ...)

DOCKER_HUB = {"docker.io", "index.docker.io", "registry-1.docker.io"}
MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json"}


def registry_creds(host):
    """(user, password) for a registry: SBOM_REGISTRY_USER/PASSWORD, else the entry that
    `docker login <host>` saved in ~/.docker/config.json. None if there isn't one."""
    user, pw = os.environ.get("SBOM_REGISTRY_USER"), os.environ.get("SBOM_REGISTRY_PASSWORD")
    if user and pw:
        return user, pw
    path = os.path.join(os.environ.get("DOCKER_CONFIG") or os.path.expanduser("~/.docker"), "config.json")
    try:
        with open(path) as f:
            auths = json.load(f).get("auths", {})
    except (OSError, ValueError):
        return None
    for key in (host, f"https://{host}", f"http://{host}"):
        saved = (auths.get(key) or {}).get("auth")
        if saved:
            user, _, pw = base64.b64decode(saved).decode().partition(":")
            return user, pw
    return None


def version_key(tag):
    """Sort key that puts 1.10 after 1.9. Used to pick the newest tags, since the v2 API
    lists tags alphabetically and has no dates."""
    return [(0, int(t)) if t.isdigit() else (1, t) for t in re.split(r"(\d+)", tag) if t]


def next_link(header, base):
    """The next-page URL from a v2 `Link: </v2/...?last=x>; rel="next"` header."""
    m = re.search(r'<([^>]+)>\s*;\s*rel="?next"?', header or "")
    return urllib.parse.urljoin(base, m.group(1)) if m else None


class V2Registry:
    """Minimal Docker Registry v2 client: tag lists and manifest digests, with the Basic and
    Bearer-token logins that registry:2, Harbor, GitLab, Nexus and Artifactory use."""

    def __init__(self, host, insecure=False):
        self.host = host
        self.base = f"{'http' if insecure else 'https'}://{host}"
        self.creds = registry_creds(host)
        self.auth = {}                      # scope -> Authorization header value

    def basic(self):
        return "Basic " + base64.b64encode(":".join(self.creds).encode()).decode()

    def get(self, path, scope, accept=None):
        url = urllib.parse.urljoin(self.base, path)
        for attempt in (1, 2):
            headers = dict(UA)
            if accept:
                headers["Accept"] = accept
            if scope in self.auth:
                headers["Authorization"] = self.auth[scope]
            try:
                return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30)
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 2:
                    raise RuntimeError(f"{self.host} rejected the scanner's login; check `docker login "
                                       f"{self.host}` or SBOM_REGISTRY_USER/PASSWORD") from None
                if e.code != 401:
                    raise RuntimeError(f"{url}: HTTP {e.code} {e.reason}") from None
                self.auth[scope] = self.login(e.headers.get("WWW-Authenticate", ""), scope)

    def login(self, challenge, scope):
        scheme, _, params = challenge.partition(" ")
        if scheme.lower() == "basic":
            if not self.creds:
                raise RuntimeError(f"{self.host} needs a login: run `docker login {self.host}` "
                                   "as the scanner's user, or set SBOM_REGISTRY_USER/PASSWORD")
            return self.basic()
        if scheme.lower() == "bearer":
            p = dict(re.findall(r'(\w+)="([^"]*)"', params))
            query = {k: v for k, v in (("service", p.get("service")), ("scope", scope)) if v}
            headers = dict(UA, **({"Authorization": self.basic()} if self.creds else {}))
            req = urllib.request.Request(p["realm"] + "?" + urllib.parse.urlencode(query), headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    data = json.load(r)
            except urllib.error.HTTPError as e:
                raise RuntimeError(f"{self.host} token request refused (HTTP {e.code}); "
                                   "check the scanner's registry login") from None
            return "Bearer " + (data.get("token") or data.get("access_token"))
        raise RuntimeError(f"{self.host}: unsupported login challenge {challenge[:60]!r}")

    def tags(self, repo):
        scope, names, url, pages = f"repository:{repo}:pull", [], f"/v2/{repo}/tags/list?n=1000", 0
        while url and pages < 100:
            with self.get(url, scope) as r:
                names += json.load(r).get("tags") or []
                url = next_link(r.headers.get("Link"), self.base)
            pages += 1
        return names

    def digest(self, repo, tag, platform):
        """The digest `docker pull` will record for repo:tag, or None if the tag has no image
        for this platform. A single-platform manifest is assumed to match."""
        with self.get(f"/v2/{repo}/manifests/{tag}", f"repository:{repo}:pull", MANIFEST_TYPES) as r:
            body = r.read()
            digest = r.headers.get("Docker-Content-Digest") or "sha256:" + hashlib.sha256(body).hexdigest()
            ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip()
        doc = json.loads(body)
        if ctype in INDEX_TYPES or doc.get("manifests"):
            os_name, arch = platform.split("/")[:2]
            if not any((m.get("platform") or {}).get("os") == os_name and
                       (m.get("platform") or {}).get("architecture") == arch
                       for m in doc.get("manifests", [])):
                return None
        return digest


def list_tags_v2(entry, reg):
    """Same as list_tags(), for a v2 registry. "Newest" means the highest version number."""
    repo = entry["repo"]
    include = re.compile(entry.get("include", ".*"))
    exclude = re.compile(entry["exclude"]) if entry.get("exclude") else None
    limit = int(entry.get("limit", 5))
    names = [t for t in reg.tags(repo) if include.search(t) and not (exclude and exclude.search(t))]
    found = []
    for name in sorted(names, key=version_key, reverse=True):
        digest = reg.digest(repo, name, entry["platform"])
        if digest:
            found.append((f"{reg.host}/{repo}:{name}", repo, name, digest))
        if len(found) >= limit:
            break
    return found


# ---------------------------------------------------------------- docker

def run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def image_present(ref):
    return run(["docker", "image", "inspect", ref], 60).returncode == 0


def pull(ref, platform):
    r = run(["docker", "pull", "--platform", platform, ref], PULL_TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError(f"pull failed: {r.stderr.strip()[-500:]}")


def local_digest(ref):
    r = run(["docker", "image", "inspect", ref, "--format",
             "{{range .RepoDigests}}{{println .}}{{end}}"], 60)
    name = ref.rsplit(":", 1)[0] if ":" in ref.rsplit("/", 1)[-1] else ref
    lines = [line.strip() for line in r.stdout.splitlines() if "@" in line]
    for line in lines:                      # the digest recorded for this repo, if there are several
        if line.split("@", 1)[0] == name:
            return line.split("@", 1)[1]
    return lines[0].split("@", 1)[1] if lines else None


def remove(ref):
    r = run(["docker", "rmi", ref], 300)
    if r.returncode != 0:
        log(f"  warning: could not remove {ref}: {r.stderr.strip()[-200:]}")


# ---------------------------------------------------------------- one image

def process(db, item, trivy, platform):
    """Pull, scan + ship (scan_all's code), record, remove. Returns a summary dict."""
    image, repo, tag, digest, registry = item
    version, db_updated, db_ready = trivy
    done = db["registry_scans"]
    had_it = image_present(image)       # never delete an image someone else put here
    started = time.time()

    try:
        log(f"  pulling {image}")
        pull(image, platform)
        actual = local_digest(image) or digest
        if actual != digest:
            log(f"  note: tag moved while listing ({digest[:19]} -> {actual[:19]})")
            digest = actual
            if done.find_one({"image": image, "digest": digest, "status": "ok"}):
                log("  already scanned at this digest, skipping")
                return {"image": image, "status": "skipped"}

        log("  scanning")
        sbom_path = scan_all.scan_image(image, REG_OUT, skip_db_update=db_ready)
        r = scan_all.ingest(db, image, sbom_path, scanner_version=version, db_updated=db_updated,
                            extra={"scanner_mode": "registry", "registry": registry, "digest": digest})
        seconds = round(time.time() - started)
        done.update_one({"image": image, "digest": digest},
                        {"$set": {"repo": repo, "tag": tag, "registry": registry,
                                  "status": "ok", "scanned_at": datetime.now(timezone.utc),
                                  "packages": r["packages"], "vulnerabilities": r["vulnerabilities"],
                                  "events": r["sent"], "seconds": seconds},
                         "$unset": {"error": ""}},
                        upsert=True)
        log(f"  ok: {r['packages']} packages, {r['vulnerabilities']} vulns, "
            f"{r['sent']} events to Wazuh, {seconds}s")
        return {"image": image, "status": "ok"}

    except Exception as e:
        err = str(e)[-800:]
        done.update_one({"image": image, "digest": digest},
                        {"$set": {"repo": repo, "tag": tag, "registry": registry,
                                  "status": "failed", "error": err,
                                  "last_attempt": datetime.now(timezone.utc)},
                         "$inc": {"attempts": 1}},
                        upsert=True)
        log(f"  FAILED: {err}")
        return {"image": image, "status": "failed"}

    finally:
        if not had_it and image_present(image):
            log(f"  removing {image}")
            remove(image)


# ---------------------------------------------------------------- one pass

def one_pass(cfg, db, dry_run=False):
    registry = cfg.get("registry", "docker.io")
    platform = cfg.get("platform", "linux/amd64")
    done = db["registry_scans"]

    clients = {}
    todo = []
    for entry in cfg["repositories"]:
        entry.setdefault("platform", platform)
        reg_name = entry.get("registry", registry)
        try:
            if reg_name in DOCKER_HUB:
                tags = list_tags(entry)
            else:
                if reg_name not in clients:
                    clients[reg_name] = V2Registry(reg_name, entry.get("insecure", cfg.get("insecure", False)))
                tags = list_tags_v2(entry, clients[reg_name])
        except Exception as e:
            log(f"could not list {entry['repo']} on {reg_name}: {e}")
            continue
        log(f"{entry['repo']}: {len(tags)} tag(s) in scope")
        for image, repo, tag, digest in tags:
            prev = done.find_one({"image": image, "digest": digest})
            if prev and prev.get("status") == "ok":
                continue
            if prev and prev.get("attempts", 0) >= MAX_ATTEMPTS:
                log(f"  giving up on {image} after {prev['attempts']} failures")
                continue
            todo.append((image, repo, tag, digest, reg_name))

    log(f"{len(todo)} image(s) not yet scanned")
    if dry_run:
        for image, _, _, digest, _ in todo:
            print(f"  would scan {image}  {digest[:19]}")
        return []
    if not todo:
        return []

    trivy = scan_all.prepare_trivy()    # one DB for the whole pass, as in scan_all.py
    results = []
    for n, item in enumerate(todo, 1):
        log(f"[{n}/{len(todo)}] {item[0]}")
        results.append(process(db, item, trivy, platform))
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan registry images once each, ship changes to Wazuh.")
    ap.add_argument("--config", default="registries.json")
    ap.add_argument("--dry-run", action="store_true", help="list what would be scanned, pull nothing")
    args = ap.parse_args(argv)

    with open(args.config) as f:
        cfg = json.load(f)

    if not args.dry_run:
        lock = scan_all.acquire_lock(OUT_DIR)  # noqa: F841 (held until exit; shared with scan_all.py)
    scan_all.check_out_dir(REG_OUT)
    scan_all.check_wazuh_log(scan_all.WAZUH_JSONL)
    db = get_db()
    scan_all.ensure_indexes(db)
    db["registry_scans"].create_index([("image", 1), ("digest", 1)], unique=True)
    log(f"Registry scanner on {scan_all.HOSTNAME}, Trivy {scan_all.TRIVY_IMAGE}")

    results = one_pass(cfg, db, dry_run=args.dry_run)
    ok = sum(r["status"] == "ok" for r in results)
    failed = sum(r["status"] == "failed" for r in results)
    log(f"Pass complete: {ok} scanned, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
