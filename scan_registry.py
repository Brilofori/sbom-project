#!/usr/bin/env python3
"""
scan_registry.py - registry mode for the SWERI SBOM pipeline.

Instead of scanning whatever happens to be on this host, this watches
container registries. Each pass it:

  1. lists the tags in every repository named in registries.json
  2. skips any image (tag + digest) that has already been scanned
  3. pulls one image, scans it with Trivy, ships the delta to Wazuh,
     records it in MongoDB, then removes the image from disk
  4. moves on to the next image

Each image is scanned once. If a tag is later rebuilt (its digest
changes) it counts as a new image and is scanned again, and the Wazuh
events show what changed.

Only one image is ever on disk at a time, which is what makes this
workable for 10-30GB images.

Registries: Docker Hub (via its own API) and any registry that speaks the
Docker Registry v2 API - Harbor, GitLab, Nexus, Artifactory, plain registry:2.
Private registries use the login saved by `docker login <host>`, or
SBOM_REGISTRY_USER / SBOM_REGISTRY_PASSWORD.

Usage:
  python3 scan_registry.py              # one pass (use with the hourly timer)
  python3 scan_registry.py --dry-run    # list what would be scanned, pull nothing
  python3 scan_registry.py --loop       # stay running, one pass per hour
  python3 scan_registry.py --config other.json
"""

import argparse
import base64
import hashlib
import fcntl
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from pymongo import MongoClient, UpdateOne

HOSTNAME = socket.gethostname()
MONGO_URI = os.environ.get("SBOM_MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("SBOM_DB", "sweri_sbom")
WAZUH_JSONL = (os.environ.get("SBOM_WAZUH_LOG") or os.environ.get("SBOM_JSONL")
               or "/var/log/sbom/trivy-findings.jsonl")       # same variable as scan_all.py
LOCK_PATH = "/tmp/sbom-scan-registry.lock"
OUT_DIR = "out/registry"
MAX_ATTEMPTS = 3          # give up on an image after this many failed passes
SCAN_TIMEOUT = 3600       # seconds; large images take a while
PULL_TIMEOUT = 3600
OFFLINE = os.environ.get("SBOM_TRIVY_OFFLINE", "").strip().lower() in ("1", "true", "yes")
WRITE_BATCH = 400         # lines written before pausing, so the Wazuh agent buffer keeps up

# Use the same pinned Trivy as scan_all.py when it's available.
try:
    from scan_all import TRIVY_IMAGE  # noqa: F401
except Exception:
    TRIVY_IMAGE = os.environ.get("SBOM_TRIVY_IMAGE", "aquasec/trivy:latest")


def redact(uri):
    """Hide the password in a connection string before it goes in a log."""
    return re.sub(r"//([^:/@]+):[^@/]*@", r"//\1:***@", uri)


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------- registry

def hub_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sweri-sbom-scanner"})
    with urllib.request.urlopen(req, timeout=30) as r:
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
    platform = entry.get("platform", "linux/amd64")
    os_name, arch = platform.split("/")[:2]

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
    lines = [l.strip() for l in r.stdout.splitlines() if "@" in l]
    for line in lines:                      # the digest recorded for this repo, if there are several
        if line.split("@", 1)[0] == name:
            return line.split("@", 1)[1]
    return lines[0].split("@", 1)[1] if lines else None


def remove(ref):
    r = run(["docker", "rmi", ref], 300)
    if r.returncode != 0:
        log(f"  warning: could not remove {ref}: {r.stderr.strip()[-200:]}")


def trivy_scan(ref, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    name = os.path.basename(out_path)
    cmd = [
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{os.path.abspath(os.path.dirname(out_path))}:/out",
        "-v", "trivy-cache:/root/.cache/trivy",
        TRIVY_IMAGE, "image",
        "--scanners", "vuln",
        "--format", "cyclonedx",
        "--output", f"/out/{name}",
        *(["--skip-db-update", "--skip-java-db-update", "--offline-scan"] if OFFLINE else []),
        ref,
    ]
    r = run(cmd, SCAN_TIMEOUT)
    if r.returncode != 0 or not os.path.exists(out_path):
        raise RuntimeError(f"trivy failed: {r.stderr.strip()[-800:]}")


# ---------------------------------------------------------------- parsing

RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0, "unknown": 0}
_REC = re.compile(r"^Upgrade (?P<pkg>.+?) to version (?P<ver>.+)$")


def trivy_severity(vuln):
    """Severity as Trivy itself reports it: the data source's vendor first, then GHSA, then NVD."""
    by_src, worst = {}, "unknown"
    for r in vuln.get("ratings") or []:
        src = (r.get("source") or {}).get("name")
        sev = (r.get("severity") or "unknown").lower()
        if RANK.get(sev, 0) > RANK.get(worst, 0):
            worst = sev
        if src not in by_src or r.get("method") != "CVSSv2":
            by_src[src] = sev
    order = [(vuln.get("source") or {}).get("name")]
    if (vuln.get("id") or "").startswith("GHSA-"):
        order.append("ghsa")
    order.append("nvd")
    return next((by_src[s] for s in order if s in by_src), worst)


def fixed_versions(vuln):
    out = {}
    for part in (vuln.get("recommendation") or "").split("; "):
        m = _REC.match(part.strip())
        if m:
            out[m["pkg"]] = m["ver"]
    return out


def fixed_version_for(fixes, comp):
    name, group = comp.get("name"), comp.get("group")
    for key in (name, f"{group}:{name}" if group else None):
        if key and key in fixes:
            return fixes[key]
    return next(iter(fixes.values())) if len(fixes) == 1 else None


def parse_sbom(path):
    with open(path, encoding="utf-8") as f:
        sbom = json.load(f)
    components = [
        {"name": c.get("name"), "version": c.get("version"), "type": c.get("type"),
         "purl": c.get("purl"), "group": c.get("group")}
        for c in sbom.get("components", [])
    ]
    ref_map = {c["bom-ref"]: c for c in sbom.get("components", []) if c.get("bom-ref")}
    vulns = []
    for v in sbom.get("vulnerabilities", []):
        fixes = fixed_versions(v)
        sev = trivy_severity(v)
        for aff in v.get("affects") or [{}]:
            comp = ref_map.get(aff.get("ref"), {})
            vulns.append({
                "cve_id": v.get("id"),
                "severity": sev,
                "package_name": comp.get("name"),
                "installed_version": comp.get("version"),
                "purl": comp.get("purl"),
                "fixed_version": fixed_version_for(fixes, comp),
            })
    return components, vulns


# ---------------------------------------------------------------- delta tracking

def identity(purl, ctype=None, name=None):
    """'pkg:deb/debian/libc6@2.36-9?arch=amd64' -> 'pkg:deb/debian/libc6'"""
    if purl:
        return purl.split("?", 1)[0].rsplit("@", 1)[0]
    return f"{ctype}:{name}"


def write_events(events):
    with open(WAZUH_JSONL, "a", encoding="utf-8") as out:
        for i, e in enumerate(events, 1):
            out.write(json.dumps(e) + "\n")
            if i % WRITE_BATCH == 0:
                out.flush()
                os.fsync(out.fileno())
                time.sleep(1)
        out.flush()
        os.fsync(out.fileno())


def track(db, image, digest, registry, components, vulns):
    """
    Compare this scan against the last known state of the same image:tag,
    write only the changes to the Wazuh log, then commit the new state.
    Events are written before state is saved, so a failed write is retried
    next pass instead of being lost.
    """
    comp_col, vuln_col = db["registry_component_state"], db["registry_vuln_state"]
    now = datetime.now(timezone.utc)
    key = {"image": image}

    names = {}
    cur_c = {}
    for c in components:
        if c.get("name"):
            ident = identity(c.get("purl"), c.get("type"), c["name"])
            cur_c.setdefault(ident, set()).add(c.get("version"))
            names[ident] = c["name"]
    cur_v = {(v["cve_id"], identity(v.get("purl"), None, v.get("package_name"))): v for v in vulns}
    open_c = {d["identity"]: d for d in comp_col.find({**key, "removed_at": None})}
    open_v = {(d["cve_id"], d["identity"]): d for d in vuln_col.find({**key, "resolved_at": None})}

    base = {"source": "trivy", "host": HOSTNAME, "scanner_mode": "registry",
            "registry": registry, "image": image, "digest": digest,
            "timestamp": now.isoformat()}
    events, ops_c, ops_v = [], [], []

    for ident, vers in cur_c.items():
        vers_l = sorted(v or "" for v in vers)
        prev = open_c.get(ident)
        pkg = names.get(ident)
        if prev is None:
            events.append({**base, "sbom_event": "component", "identity": ident,
                           "package_name": pkg, "installed_version": ", ".join(vers_l)})
        elif prev["versions"] != vers_l:
            events.append({**base, "sbom_event": "component_changed", "identity": ident,
                           "package_name": pkg, "previous_version": ", ".join(prev["versions"]),
                           "installed_version": ", ".join(vers_l)})
        ops_c.append(UpdateOne({**key, "identity": ident, "removed_at": None},
                               {"$set": {"versions": vers_l, "package_name": pkg, "last_seen": now},
                                "$setOnInsert": {"first_seen": now}}, upsert=True))
    for ident in open_c.keys() - cur_c.keys():
        events.append({**base, "sbom_event": "component_removed", "identity": ident,
                       "package_name": open_c[ident].get("package_name")})
        ops_c.append(UpdateOne({**key, "identity": ident, "removed_at": None},
                               {"$set": {"removed_at": now}}))

    for (cve, ident), v in cur_v.items():
        if (cve, ident) not in open_v:
            events.append({**base, "sbom_event": "vulnerability", "cve_id": cve, "identity": ident,
                           "package_name": v.get("package_name"), "severity": v.get("severity"),
                           "installed_version": v.get("installed_version"),
                           "fixed_version": v.get("fixed_version")})
        ops_v.append(UpdateOne({**key, "cve_id": cve, "identity": ident, "resolved_at": None},
                               {"$set": {"last_seen": now, "severity": v.get("severity"),
                                         "package_name": v.get("package_name"),
                                         "installed_version": v.get("installed_version")},
                                "$setOnInsert": {"first_seen": now}}, upsert=True))
    for (cve, ident) in open_v.keys() - cur_v.keys():
        events.append({**base, "sbom_event": "vulnerability_resolved", "cve_id": cve,
                       "identity": ident, "package_name": open_v[(cve, ident)].get("package_name")})
        ops_v.append(UpdateOne({**key, "cve_id": cve, "identity": ident, "resolved_at": None},
                               {"$set": {"resolved_at": now}}))

    if events:
        write_events(events)            # 1) deliver
    if ops_c:
        comp_col.bulk_write(ops_c)      # 2) then commit
    if ops_v:
        vuln_col.bulk_write(ops_v)
    return events


# ---------------------------------------------------------------- one image

def process(db, image, repo, tag, digest, registry, platform):
    """Pull, scan, ship, record, remove. Returns a summary dict."""
    done = db["registry_scans"]
    safe = image.replace("/", "_").replace(":", "_")
    out_path = os.path.join(OUT_DIR, f"{safe}@{digest.split(':')[-1][:12]}.json")
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
        trivy_scan(image, out_path)
        components, vulns = parse_sbom(out_path)
        events = track(db, image, digest, registry, components, vulns)

        db["scans"].insert_one({
            "host": HOSTNAME, "scanner_mode": "registry", "registry": registry,
            "image": image, "repo": repo, "tag": tag, "digest": digest,
            "scanned_at": datetime.now(timezone.utc), "source_file": out_path,
            "component_count": len(components), "vulnerability_count": len(vulns),
            "components": [{k: c[k] for k in ("name", "version", "type", "purl")} for c in components],
            "vulnerabilities": vulns,
        })
        done.update_one({"image": image, "digest": digest},
                        {"$set": {"repo": repo, "tag": tag, "registry": registry,
                                  "status": "ok", "scanned_at": datetime.now(timezone.utc),
                                  "components": len(components), "vulnerabilities": len(vulns),
                                  "events": len(events),
                                  "seconds": round(time.time() - started)},
                         "$unset": {"error": ""}},
                        upsert=True)
        log(f"  ok: {len(components)} components, {len(vulns)} vulns, "
            f"{len(events)} events to Wazuh, {round(time.time() - started)}s")
        return {"image": image, "status": "ok", "events": len(events)}

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

    def get(self, path, scope, accept=None):
        url = urllib.parse.urljoin(self.base, path)
        for attempt in (1, 2):
            headers = {"User-Agent": "sweri-sbom-scanner"}
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
            return "Basic " + base64.b64encode(":".join(self.creds).encode()).decode()
        if scheme.lower() == "bearer":
            p = dict(re.findall(r'(\w+)="([^"]*)"', params))
            query = {k: v for k, v in (("service", p.get("service")), ("scope", scope)) if v}
            headers = {"User-Agent": "sweri-sbom-scanner"}
            if self.creds:
                headers["Authorization"] = "Basic " + base64.b64encode(":".join(self.creds).encode()).decode()
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

    results = []
    for n, (image, repo, tag, digest, reg_name) in enumerate(todo, 1):
        log(f"[{n}/{len(todo)}] {image}")
        results.append(process(db, image, repo, tag, digest, reg_name, platform))
    return results


def preflight():
    try:
        os.makedirs(os.path.dirname(WAZUH_JSONL), exist_ok=True)
        open(WAZUH_JSONL, "a").close()
    except OSError as e:
        sys.exit(f"Cannot write {WAZUH_JSONL}: {e}\n"
                 f"Fix: sudo mkdir -p /var/log/sbom && sudo chown $USER /var/log/sbom")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    try:
        client.admin.command("ping")
    except Exception as e:
        sys.exit(f"MongoDB not reachable at {redact(MONGO_URI)}: {e}")
    db = client[DB_NAME]
    db["registry_scans"].create_index([("image", 1), ("digest", 1)], unique=True)
    db["registry_component_state"].create_index([("image", 1), ("identity", 1), ("removed_at", 1)])
    db["registry_vuln_state"].create_index([("image", 1), ("cve_id", 1), ("identity", 1), ("resolved_at", 1)])
    return db


def main():
    ap = argparse.ArgumentParser(description="Scan registry images once each, ship deltas to Wazuh.")
    ap.add_argument("--config", default="registries.json")
    ap.add_argument("--dry-run", action="store_true", help="list what would be scanned, pull nothing")
    ap.add_argument("--loop", action="store_true", help="keep running, one pass per interval")
    ap.add_argument("--interval", type=int, default=3600, help="seconds between passes with --loop")
    args = ap.parse_args()

    with open(args.config) as f:
        cfg = json.load(f)

    lock = open(LOCK_PATH, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit("Another scan_registry run is still going; exiting.")

    db = preflight()
    log(f"Registry scanner on {HOSTNAME}, Trivy {TRIVY_IMAGE}")

    while True:
        results = one_pass(cfg, db, dry_run=args.dry_run)
        ok = sum(r["status"] == "ok" for r in results)
        failed = sum(r["status"] == "failed" for r in results)
        log(f"Pass complete: {ok} scanned, {failed} failed")
        if not args.loop or args.dry_run:
            sys.exit(1 if failed else 0)
        log(f"Sleeping {args.interval}s")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
