#!/usr/bin/env python3
"""
scan_registry.py - registry mode for the SWERI SBOM pipeline.

Instead of scanning the images on this host, this watches container registries.
Each pass it:

  1. lists the tags in every repository in the registry (or only those named in
     registries.json)
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
import shutil
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
# Disk space to leave free on Docker's disk after a pull, in GB. While it is scanned an image
# needs about five times its download size: Docker keeps it unpacked (2-3x the compressed
# download) and Trivy writes a second, uncompressed copy to scan.
try:
    MIN_FREE_GB = float(os.environ.get("SBOM_MIN_FREE_GB", "10"))
except ValueError:
    MIN_FREE_GB = 10.0
SPACE_FACTOR = 5
UA = {"User-Agent": "sweri-sbom-scanner"}


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def tag_filter(entry):
    """The config entry's include/exclude regexes as one test, and its `limit`."""
    include = re.compile(entry.get("include", ".*"))
    exclude = re.compile(entry["exclude"]) if entry.get("exclude") else None
    return (lambda tag: bool(include.search(tag)) and not (exclude and exclude.search(tag)),
            int(entry.get("limit", 5)))


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
    wanted, limit = tag_filter(entry)
    os_name, arch = entry.get("platform", "linux/amd64").split("/")[:2]

    url = (f"https://hub.docker.com/v2/repositories/{repo}/tags"
           f"?page_size=100&ordering=last_updated")
    found, pages = [], 0
    while url and len(found) < limit and pages < 10:
        data = hub_get(url)
        pages += 1
        for t in data.get("results", []):
            name = t.get("name", "")
            if not wanted(name):
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

    def size(self, repo, ref, platform):
        """Download size in bytes of repo@ref for this platform (layers + config), from the
        manifest. None if the registry doesn't say."""
        scope = f"repository:{repo}:pull"
        with self.get(f"/v2/{repo}/manifests/{ref}", scope, MANIFEST_TYPES) as r:
            doc = json.load(r)
        if doc.get("manifests"):                      # multi-platform: find ours
            os_name, arch = platform.split("/")[:2]
            mine = [m for m in doc["manifests"]
                    if (m.get("platform") or {}).get("os") == os_name
                    and (m.get("platform") or {}).get("architecture") == arch]
            if not mine:
                return None
            with self.get(f"/v2/{repo}/manifests/{mine[0]['digest']}", scope, MANIFEST_TYPES) as r:
                doc = json.load(r)
        layers = doc.get("layers")
        if not layers:
            return None
        sizes = [layer.get("size") for layer in layers] + [(doc.get("config") or {}).get("size", 0)]
        return sum(sizes) if all(isinstance(s, int) for s in sizes) else None

    def catalog(self):
        """Every repository in the registry. The login needs permission to list them."""
        names, url, pages = [], "/v2/_catalog?n=1000", 0
        while url and pages < 100:
            with self.get(url, "registry:catalog:*") as r:
                names += json.load(r).get("repositories") or []
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
    wanted, limit = tag_filter(entry)
    names = [t for t in reg.tags(repo) if wanted(t)]
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


def docker_root():
    """The folder Docker keeps images in, or None if Docker won't say."""
    try:
        r = run(["docker", "info", "--format", "{{.DockerRootDir}}"], 60)
    except subprocess.TimeoutExpired:
        return None
    root = r.stdout.strip() if r.returncode == 0 else ""
    return root if root and os.path.isdir(root) else None


def space_problem(size, root):
    """A message if pulling an image of `size` bytes would leave less than MIN_FREE_GB free
    on Docker's disk, else None. With an unknown size, only the minimum is checked."""
    if not root:
        return None
    try:
        free = shutil.disk_usage(root).free
    except OSError:
        return None
    needed = SPACE_FACTOR * (size or 0) + MIN_FREE_GB * 1e9
    if free >= needed:
        return None
    return (f"not enough disk space on {root}: {free / 1e9:.1f} GB free, about "
            f"{needed / 1e9:.1f} GB needed (image {(size or 0) / 1e9:.1f} GB, plus "
            f"{MIN_FREE_GB:g} GB kept free)")


def remove(ref):
    r = run(["docker", "rmi", ref], 300)
    if r.returncode != 0:
        log(f"  warning: could not remove {ref}: {r.stderr.strip()[-200:]}")


# ---------------------------------------------------------------- one image

def process(db, item, trivy, platform, size=None, root=None):
    """Check space, pull, scan + ship (scan_all's code), record, remove. Returns a summary."""
    image, repo, tag, digest, registry = item
    version, db_updated, db_ready = trivy
    done = db["registry_scans"]
    had_it = image_present(image)       # never delete an image someone else put here
    started = time.time()

    short = None if had_it else space_problem(size, root)
    if short:                           # not the image's fault: try again next pass, no attempt used
        log(f"  skipped: {short}")
        done.update_one({"image": image, "digest": digest},
                        {"$set": {"repo": repo, "tag": tag, "registry": registry,
                                  "status": "failed", "error": short,
                                  "last_attempt": datetime.now(timezone.utc)},
                         "$setOnInsert": {"attempts": 0}},
                        upsert=True)
        return {"image": image, "status": "failed", "error": short}

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
        return {"image": image, "status": "failed", "error": err.strip().splitlines()[-1][-300:]
                if err.strip() else "unknown error"}

    finally:
        if not had_it and image_present(image):
            log(f"  removing {image}")
            remove(image)


# ---------------------------------------------------------------- one pass

def repositories(cfg, clients):
    """The repositories to scan. If the config lists none, every repository in the registry,
    each using the config's own include, exclude and limit, minus any matching exclude_repos."""
    if "repositories" in cfg:
        return cfg["repositories"]
    registry = cfg.get("registry", "docker.io")
    if registry in DOCKER_HUB:
        raise RuntimeError("Docker Hub can't list all its repositories; "
                           "name them under \"repositories\" in the config")
    if registry not in clients:
        clients[registry] = V2Registry(registry, cfg.get("insecure", False))
    skip = re.compile(cfg["exclude_repos"]) if cfg.get("exclude_repos") else None
    names = [n for n in clients[registry].catalog() if not (skip and skip.search(n))]
    log(f"{registry}: {len(names)} repositories found")
    shared = {k: cfg[k] for k in ("include", "exclude", "limit") if k in cfg}
    return [{"repo": n, **shared} for n in sorted(names)]


def one_pass(cfg, db, dry_run=False):
    registry = cfg.get("registry", "docker.io")
    platform = cfg.get("platform", "linux/amd64")
    done = db["registry_scans"]

    clients = {}
    todo = []
    unlisted = []                       # registries/repositories that couldn't be read
    try:
        entries = repositories(cfg, clients)
    except Exception as e:
        log(f"could not list the repositories in {registry}: {e}")
        unlisted.append({"image": registry, "status": "unlisted", "error": str(e), "whole": True})
        entries = []
    for entry in entries:
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
            unlisted.append({"image": f"{reg_name}/{entry['repo']}", "status": "unlisted",
                             "error": str(e)})
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

    if entries and len(unlisted) == len(entries):   # couldn't read any of them
        for u in unlisted:
            u["whole"] = True
    log(f"{len(todo)} image(s) not yet scanned")
    if dry_run:
        for image, _, _, digest, _ in todo:
            print(f"  would scan {image}  {digest[:19]}")
        return unlisted
    if not todo:
        return unlisted

    trivy = scan_all.prepare_trivy()    # one DB for the whole pass, as in scan_all.py
    root = docker_root()
    results = []
    for n, item in enumerate(todo, 1):
        image, repo, _, digest, reg_name = item
        size = None
        if reg_name in clients:
            try:
                size = clients[reg_name].size(repo, digest, platform)
            except Exception:
                pass                        # size unknown: only the minimum free space is checked
        log(f"[{n}/{len(todo)}] {image}" + (f"  ({size / 1e9:.1f} GB)" if size else ""))
        results.append(process(db, item, trivy, platform, size=size, root=root))
    return unlisted + results


def main(argv=None):
    return scan_all.reported("registry", _main, argv)


def _main(argv):
    ap = argparse.ArgumentParser(description="Scan registry images once each, ship changes to Wazuh.")
    ap.add_argument("--config", default="registries.json")
    ap.add_argument("--dry-run", action="store_true", help="list what would be scanned, pull nothing")
    args = ap.parse_args(argv)

    try:
        with open(args.config) as f:
            cfg = json.load(f)
    except FileNotFoundError:
        sys.exit(f"No {args.config}. Create it from the example:  cp registries.example.json "
                 "registries.json  then put the registry's address in it (README, \"Setting it up\").")

    if not args.dry_run:
        lock = scan_all.acquire_lock(OUT_DIR)  # noqa: F841 (held until exit; shared with scan_all.py)
    scan_all.check_out_dir(REG_OUT)
    scan_all.check_wazuh_log(scan_all.WAZUH_JSONL)
    db = get_db()
    if not args.dry_run:            # a dry run only reads; it never changes the database
        for name in scan_all.migrate_legacy_state(db):
            log(f"old-format state set aside as {name} (kept, not deleted)")
        scan_all.ensure_indexes(db)
        db["registry_scans"].create_index([("image", 1), ("digest", 1)], unique=True)
    log(f"Registry scanner on {scan_all.HOSTNAME}, Trivy {scan_all.TRIVY_IMAGE}")

    results = one_pass(cfg, db, dry_run=args.dry_run)
    ok = sum(r["status"] == "ok" for r in results)
    failed = sum(r["status"] == "failed" for r in results)
    unlisted = [r for r in results if r["status"] == "unlisted"]
    if not args.dry_run:
        problems = [f"{r['image']}: {r['error']}" for r in results if r.get("error")]
        if any(r.get("whole") for r in unlisted) or (failed and not ok):
            status = "error"            # the registry couldn't be read, or no image could be scanned
        else:
            status = "failed" if failed or unlisted else "ok"
        scan_all.report_run("registry", ok, failed + len(unlisted), problems, status=status)
    log(f"Pass complete: {ok} scanned, {failed} failed"
        + (f", {len(unlisted)} could not be listed" if unlisted else ""))
    return 1 if failed or unlisted else 0


if __name__ == "__main__":
    sys.exit(main())
