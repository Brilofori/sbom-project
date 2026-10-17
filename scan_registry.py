#!/usr/bin/env python3
"""
scan_registry.py - registry mode for the SWERI SBOM pipeline.

Instead of scanning the images on this host, this watches container registries.
Each pass it:

  1. lists the tags in every repository in the registry (or only those named in
     registries.json)
  2. skips any image (tag + digest) that has already been scanned, and scans tags that
     share a digest only once
  3. scans each remaining image and ships the changes to Wazuh exactly as scan_all.py
     does (same Trivy, parsing, change tracking and events): an identical copy already
     on this machine is scanned in place; otherwise the image is downloaded by its
     digest (never by tag, so tags on this machine are never changed), scanned, and
     removed again

Each image is scanned once. If a tag is later rebuilt (its digest changes) it is
scanned again, and the Wazuh events show what changed. Only one downloaded image is on
disk at a time, which is what makes this workable for 10-30GB images.

With --local it first scans every image already on this machine, as scan_all.py does,
then downloads from the registry only what isn't here: the setup for a build server.

Registries: Docker Hub (via its own API) and any registry that speaks the Docker
Registry v2 API - Harbor, GitLab, Nexus, Artifactory, plain registry:2. Private
registries use the login saved by `docker login <host>`, or
SBOM_REGISTRY_USER / SBOM_REGISTRY_PASSWORD.

Usage:
  python3 scan_registry.py              # one pass (use with the hourly timer)
  python3 scan_registry.py --local      # this machine's images first, then the registry
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
from typing import NamedTuple

import scan_all
from sbom_common import OUT_DIR, get_db

REG_OUT = OUT_DIR / "registry"   # latest CycloneDX file per registry image
MAX_ATTEMPTS = 3                 # give up on an image after this many failed passes
PULL_TIMEOUT = 3600              # seconds
REMOVE_TRIES, REMOVE_WAIT = 3, 20  # chances Docker gets to answer before a download is left in place
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
        self.manifests = {}                 # (repo, ref, platform) -> manifest, see manifest()

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

    def manifest(self, repo, ref, platform):
        """The image manifest of repo@ref for this platform (the one for our platform, if ref
        is a multi-platform index), or None if there is no image for it. Kept, since size()
        and config_digest() both need it."""
        key = (repo, ref, platform)
        if key not in self.manifests:
            scope = f"repository:{repo}:pull"
            with self.get(f"/v2/{repo}/manifests/{ref}", scope, MANIFEST_TYPES) as r:
                doc = json.load(r)
            if doc.get("manifests"):                  # multi-platform: find ours
                os_name, arch = platform.split("/")[:2]
                mine = [m for m in doc["manifests"]
                        if (m.get("platform") or {}).get("os") == os_name
                        and (m.get("platform") or {}).get("architecture") == arch]
                doc = None
                if mine:
                    with self.get(f"/v2/{repo}/manifests/{mine[0]['digest']}", scope, MANIFEST_TYPES) as r:
                        doc = json.load(r)
            self.manifests[key] = doc
        return self.manifests[key]

    def size(self, repo, ref, platform):
        """Download size in bytes of repo@ref for this platform (layers + config), from the
        manifest. None if the registry doesn't say."""
        doc = self.manifest(repo, ref, platform) or {}
        layers = doc.get("layers")
        if not layers:
            return None
        sizes = [layer.get("size") for layer in layers] + [(doc.get("config") or {}).get("size", 0)]
        return sum(sizes) if all(isinstance(s, int) for s in sizes) else None

    def config_digest(self, repo, ref, platform):
        """The digest of the image's configuration, which Docker's classic image store uses as
        the image ID: how an image on this machine is recognised when Docker has no record of
        the registry digest it came from. None if the registry doesn't say."""
        return ((self.manifest(repo, ref, platform) or {}).get("config") or {}).get("digest")

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


def split_ref(ref):
    """("host/repo", "tag") for "host/repo:tag"; a ':' that belongs to a registry port isn't
    a tag. The tag is None if there isn't one."""
    name, sep, tag = ref.rpartition(":")
    if sep and "/" not in tag:
        return name, tag
    return ref, None


def digest_ref(image, digest):
    """The reference for exactly this digest of the image's repository: repo@sha256:..."""
    return f"{split_ref(image)[0]}@{digest}"


def pull(ref, platform):
    r = run(["docker", "pull", "--platform", platform, ref], PULL_TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError(f"pull failed: {r.stderr.strip()[-500:]}")


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
    """Remove an image this pass downloaded, if it is here. Returns None, or a note saying it
    was left on this machine. Removing is the one step that can't be undone, so it is only
    done once Docker confirms the image is there; Docker gets a few chances to answer."""
    problem = None
    for n in range(REMOVE_TRIES):
        if n:
            time.sleep(REMOVE_WAIT)
        try:
            if scan_all.image_id(ref) is None:
                return None
            log(f"  removing {ref}")
            r = run(["docker", "rmi", ref], 300)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            problem = f"Docker didn't answer ({e})"
            continue
        if r.returncode == 0:
            return None
        problem = r.stderr.strip()[-200:] or f"docker rmi exited {r.returncode}"
        break                           # Docker answered: asking again won't change its mind
    note = f"left {ref} on this machine: {problem}. Remove it with: docker rmi {ref}"
    log(f"  warning: {note}")
    return note


# ---------------------------------------------------------------- one image

def mark_done(done, item, same_as, now):
    """Record a tag as scanned because the identical image was scanned as `same_as`."""
    image, repo, tag, digest, registry = item
    done.update_one({"image": image, "digest": digest},
                    {"$set": {"repo": repo, "tag": tag, "registry": registry, "status": "ok",
                              "scanned_at": now, "same_as": same_as},
                     "$unset": {"error": ""}},
                    upsert=True)


def process(db, item, trivy, platform, size=None, root=None, others=(), seen=None):
    """Scan one registry image and ship the changes (scan_all's code), then record it.

    The image is read by its digest (repo@sha256:...), never by its tag, so what is scanned
    is exactly the registry's image, whatever the tags on this machine point to, and no tag
    here is ever changed. If this machine already has the image it is scanned where it is
    and left alone; otherwise it is downloaded, scanned and removed again. `others` are the
    registry's other tags for the same image: they are recorded as scanned too, and named in
    the events' other_tags. `seen` (--local) maps the IDs of the images this run scanned on
    this machine to the names they were reported under: if the image turns out to be one of
    them, it is recorded as the same image, not scanned and reported a second time."""
    image, repo, tag, digest, registry = item
    done = db["registry_scans"]
    by_digest = digest_ref(image, digest)
    try:
        had_it = scan_all.image_id(by_digest) is not None   # never delete what was already here
        short = None if had_it else space_problem(size, root)
    except RuntimeError as e:          # Docker didn't answer: leave this image alone until next pass
        had_it, short = True, str(e)
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
        result = scan_one(db, item, trivy, platform, by_digest, had_it, others, seen)
    finally:
        left = None if had_it else remove(by_digest)
    if left:
        result["warning"] = left
    return result


def scan_one(db, item, trivy, platform, by_digest, had_it, others, seen):
    """The middle of process(): download unless here, then scan, ship and record. Returns the
    result. A failure is recorded, and after MAX_ATTEMPTS of them with the same
    SBOM_SCAN_TIMEOUT the image isn't tried again (one_pass)."""
    image, repo, tag, digest, registry = item
    version, db_updated, db_ready = trivy
    done = db["registry_scans"]
    started = time.time()
    try:
        if had_it:
            log("  already on this machine: scanning it there, nothing to download")
        else:
            log(f"  downloading {by_digest}")
            pull(by_digest, platform)
        same_as = recognise(by_digest, seen)
        if same_as:
            log(f"  the same image as {same_as}, scanned on this machine above")
            now = datetime.now(timezone.utc)
            for one in (item, *others):
                mark_done(done, one, same_as, now)
            return {"image": image, "status": "same"}

        log("  scanning")
        sbom_path = scan_all.scan_image(image, REG_OUT, skip_db_update=db_ready, target=by_digest)
        extra = {"scanner_mode": "registry", "registry": registry, "digest": digest}
        if others:
            extra["other_tags"] = ", ".join(other[0] for other in others)
        r = scan_all.ingest(db, image, sbom_path, scanner_version=version, db_updated=db_updated,
                            extra=extra)
        scan_all.forget(db, scan_all.HOSTNAME, [other[0] for other in others])
        seconds = round(time.time() - started)
        now = datetime.now(timezone.utc)
        done.update_one({"image": image, "digest": digest},
                        {"$set": {"repo": repo, "tag": tag, "registry": registry,
                                  "status": "ok", "scanned_at": now,
                                  "packages": r["packages"], "vulnerabilities": r["vulnerabilities"],
                                  "events": r["sent"], "seconds": seconds},
                         "$unset": {"error": ""}},
                        upsert=True)
        for other in others:
            mark_done(done, other, image, now)
        log(f"  ok: {r['packages']} packages, {r['vulnerabilities']} vulns, "
            f"{r['sent']} events to Wazuh, {seconds}s")
        return {"image": image, "status": "ok"}

    except Exception as e:
        err = str(e)[-800:]
        prev = done.find_one({"image": image, "digest": digest}) or {}
        # A new SBOM_SCAN_TIMEOUT starts the count again: it may be what makes the scan work
        tries = 1 + (prev.get("attempts", 0) if prev.get("timeout") == scan_all.SCAN_TIMEOUT else 0)
        done.update_one({"image": image, "digest": digest},
                        {"$set": {"repo": repo, "tag": tag, "registry": registry,
                                  "status": "failed", "error": err, "attempts": tries,
                                  "timeout": scan_all.SCAN_TIMEOUT,
                                  "last_attempt": datetime.now(timezone.utc)}},
                        upsert=True)
        log(f"  FAILED: {err}")
        reason = err.strip().splitlines()[-1][-300:] if err.strip() else "unknown error"
        if tries >= MAX_ATTEMPTS:
            reason += f" (gave up after {tries} tries)"
        return {"image": image, "status": "failed", "error": reason}


def recognise(ref, seen):
    """If `ref` is an image this run already scanned on this machine (--local), the name it
    was reported under; else None."""
    if not seen:
        return None
    try:
        return seen.get(scan_all.image_id(ref))
    except RuntimeError:
        return None


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


class OnThisMachine(NamedTuple):
    """What --local found on this machine, for the registry pass that follows it. An image
    is known by its image ID and by every registry digest (repo@sha256:...) Docker has
    recorded for it."""
    names: frozenset    # every image name (repo:tag) here
    scanned: dict       # ID or digest of each image scanned here -> the name it was reported under
    failed: frozenset   # IDs and digests of the images here whose scan failed


NOTHING_HERE = OnThisMachine(frozenset(), {}, frozenset())


def one_pass(cfg, db, dry_run=False, trivy=None, here=NOTHING_HERE, retry=False):
    """One registry pass. With --local, `here` is what this run already found and scanned on
    this machine, so none of it is scanned again. `retry` (--retry-failed): images given up
    on are tried again."""
    registry = cfg.get("registry", "docker.io")
    platform = cfg.get("platform", "linux/amd64")
    done = db["registry_scans"]

    clients = {}
    todo = []
    unlisted = []                       # registries/repositories that couldn't be read
    stuck = {}                          # digest -> failures, for images given up on (scan_one)
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
            if done.find_one({"image": image, "digest": digest, "status": "ok"}):
                continue
            # Given up on: counted per image, so tags that share a digest don't each get their
            # own tries, and per SBOM_SCAN_TIMEOUT, so a new timeout gives the image new tries
            given_up = None if retry or digest in stuck else done.find_one(
                {"digest": digest, "status": "failed", "timeout": scan_all.SCAN_TIMEOUT,
                 "attempts": {"$gte": MAX_ATTEMPTS}})
            if given_up:
                stuck[digest] = given_up["attempts"]
            todo.append((image, repo, tag, digest, reg_name))

    if entries and len(unlisted) == len(entries):   # couldn't read any of them
        for u in unlisted:
            u["whole"] = True

    # Tags that need no scan of their own: the same image was scanned on this machine in this
    # run (--local), or under another tag in an earlier pass. They're recorded as done.
    skipped, already, remaining, abandoned = [], [], [], {}
    for item in todo:
        image, repo, _, digest, reg_name = item
        # How this machine may know the image: the digest Docker recorded when it was pulled
        # or pushed, or its image ID (the digest itself on Docker's containerd image store,
        # the config digest on the classic store)
        keys = [digest_ref(image, digest), digest]
        if here.names and reg_name in clients:
            try:
                keys.append(clients[reg_name].config_digest(repo, digest, platform))
            except Exception:
                pass                    # the registry won't say; the other two still apply
        seen_as = next((here.scanned[k] for k in keys if k in here.scanned), None)
        if seen_as:
            already.append((item, seen_as))
            continue
        if any(k in here.failed for k in keys):
            log(f"  {image}: its scan on this machine failed above, so it isn't downloaded")
            continue
        prev = done.find_one({"digest": digest, "status": "ok"})
        if prev:
            already.append((item, prev.get("same_as") or prev["image"]))
        elif digest in stuck:
            log(f"  giving up on {image}: it failed {stuck[digest]} times")
            abandoned.setdefault(digest, {"image": image, "status": "abandoned"})
        elif image in here.names:
            # Scanning the registry's version under the same name as this machine's image
            # would mix two different images in one record, and this machine's was scanned
            # above. The run summary counts these as skipped.
            log(f"  {image}: skipped, this machine has a different image under this name; "
                "the registry's is scanned once they match")
            skipped.append({"image": image, "status": "skipped"})
        else:
            remaining.append(item)
    if already:
        log(f"{len(already)} tag(s) already scanned as an identical image")
    if already and not dry_run:
        now = datetime.now(timezone.utc)
        for item, same_as in already:
            mark_done(done, item, same_as, now)

    groups = {}                         # tags that share a digest are one image: scan it once
    for item in remaining:
        groups.setdefault(item[3], []).append(item)
    plan = []
    for digest, items in groups.items():
        by_name = {item[0]: item for item in items}
        primary = scan_all.choose_primary(db, scan_all.HOSTNAME, list(by_name), digest=digest)
        plan.append((by_name[primary], [item for name, item in by_name.items() if name != primary]))

    log(f"{len(plan)} image(s) not yet scanned" +
        (f" ({len(remaining)} tags)" if len(remaining) != len(plan) else ""))
    unscanned = unlisted + list(abandoned.values()) + skipped
    if dry_run:
        for (image, _, _, digest, _), others in plan:
            print(f"  would scan {image}  {digest[:19]}" + also_tagged([o[0] for o in others]))
        return unscanned
    if not plan:
        return unscanned

    trivy = trivy or scan_all.prepare_trivy()   # one DB for the whole pass, as in scan_all.py
    root = docker_root()
    results = []
    for n, (item, others) in enumerate(plan, 1):
        image, repo, _, digest, reg_name = item
        size = None
        if reg_name in clients:
            try:
                size = clients[reg_name].size(repo, digest, platform)
            except Exception:
                pass                        # size unknown: only the minimum free space is checked
        log(f"[{n}/{len(plan)}] {image}" + (f"  ({size / 1e9:.1f} GB)" if size else "") +
            also_tagged([o[0] for o in others]))
        results.append(process(db, item, trivy, platform, size=size, root=root, others=others,
                               seen=here.scanned))
    return unscanned + results


def also_tagged(names):
    return f"  (also tagged {', '.join(names)})" if names else ""


def scan_machine(db, rows, dry_run):
    """--local: scan the images already on this machine, once per image and without
    downloading anything (scan_all.py's code). Returns (trivy, here, results): the Trivy
    versions, for the registry pass to reuse; what is on this machine and how its scans
    went (OnThisMachine); and one result per image, in this script's form."""
    ids = {row["name"]: row["id"] for row in rows if row["name"]}
    names = sorted(ids)
    groups = scan_all.group_by_image(names, ids)
    log(f"This machine: {len(groups)} image(s) ({len(names)} tags), scanned without downloading")
    if not groups:
        return None, NOTHING_HERE, []

    trivy, results, reported = None, [], {}     # reported: image ID -> the name it was reported under
    if dry_run:
        for group in groups:
            primary = scan_all.choose_primary(db, scan_all.HOSTNAME, group, image_id=ids[group[0]])
            print(f"  would scan {primary}" + also_tagged([n for n in group if n != primary]))
            reported[ids[primary]] = primary
    else:
        trivy = scan_all.prepare_trivy()
        for r in scan_all.scan_local(db, names, ids, trivy, say=log):
            if "error" in r:
                results.append({"image": r["image"], "status": "failed",
                                "error": r.get("detail") or r["error"]})
            else:
                results.append({"image": r["image"], "status": "ok"})
                reported[ids[r["image"]]] = r["image"]
    failed_ids = set(ids.values()) - set(reported)
    scanned = dict(reported)            # by image ID, and by every registry digest Docker has for it
    scanned.update({row["digest_ref"]: reported[row["id"]] for row in rows
                    if row["digest_ref"] and row["id"] in reported})
    failed = failed_ids | {row["digest_ref"] for row in rows
                           if row["digest_ref"] and row["id"] in failed_ids}
    return trivy, OnThisMachine(frozenset(names), scanned, frozenset(failed)), results


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    return scan_all.reported("local+registry" if "--local" in argv else "registry", _main, argv)


def _main(argv):
    ap = argparse.ArgumentParser(description="Scan registry images once each, ship changes to Wazuh.")
    ap.add_argument("--config", default="registries.json")
    ap.add_argument("--dry-run", action="store_true", help="list what would be scanned, pull nothing")
    ap.add_argument("--local", action="store_true",
                    help="first scan every image already on this machine, without downloading "
                         "it; then download from the registry only what isn't here")
    ap.add_argument("--retry-failed", action="store_true",
                    help=f"give images that failed {MAX_ATTEMPTS} times, and are no longer tried, "
                         f"another {MAX_ATTEMPTS} tries")
    args = ap.parse_args(argv)
    scan_all.check_settings()

    try:
        with open(args.config) as f:
            cfg = json.load(f)
    except FileNotFoundError:
        sys.exit(f"No {args.config}. Create it from the example:  cp registries.example.json "
                 "registries.json  then put the registry's address in it (README, \"Setting it up\").")

    if not args.dry_run:
        lock = scan_all.acquire_lock(OUT_DIR)  # noqa: F841 (held until exit; shared with scan_all.py)
    rows = scan_all.local_images() if args.local else []
    scan_all.check_out_dir(REG_OUT)
    scan_all.check_wazuh_log(scan_all.WAZUH_JSONL)
    db = get_db()
    if not args.dry_run:            # a dry run only reads; it never changes the database
        for name in scan_all.migrate_legacy_state(db):
            log(f"old-format state set aside as {name} (kept, not deleted)")
        scan_all.ensure_indexes(db)
        db["registry_scans"].create_index([("image", 1), ("digest", 1)], unique=True)
        if args.retry_failed:
            n = db["registry_scans"].update_many({"status": "failed", "attempts": {"$gt": 0}},
                                                 {"$set": {"attempts": 0}}).modified_count
            log(f"{n} failed image(s) get new tries")
    log(f"Registry scanner on {scan_all.HOSTNAME}, Trivy {scan_all.TRIVY_IMAGE}")

    trivy, here, results = None, NOTHING_HERE, []
    if args.local:
        trivy, here, results = scan_machine(db, rows, args.dry_run)
    results += one_pass(cfg, db, dry_run=args.dry_run, trivy=trivy, here=here, retry=args.retry_failed)
    ok = sum(r["status"] == "ok" for r in results)
    failed = sum(r["status"] == "failed" for r in results)
    skipped = sum(r["status"] == "skipped" for r in results)
    abandoned = sum(r["status"] == "abandoned" for r in results)
    unlisted = [r for r in results if r["status"] == "unlisted"]
    if not args.dry_run:
        warnings = [f"{r['image']}: {r['warning']}" for r in results if r.get("warning")]
        problems = [f"{r['image']}: {r['error']}" for r in results if r.get("error")] + warnings
        if any(r.get("whole") for r in unlisted) or (failed and not ok):
            status = "error"            # the registry couldn't be read, or no image could be scanned
        else:                           # a download left on the machine needs someone too
            status = "failed" if failed or unlisted or warnings else "ok"
        scan_all.report_run("local+registry" if args.local else "registry", ok, failed + len(unlisted),
                            problems, status=status, skipped=skipped, abandoned=abandoned)
    log(f"Pass complete: {ok} scanned, {failed} failed"
        + (f", {skipped} skipped" if skipped else "")
        + (f", {abandoned} given up on" if abandoned else "")
        + (f", {len(unlisted)} could not be listed" if unlisted else ""))
    return 1 if failed or unlisted else 0


if __name__ == "__main__":
    sys.exit(main())
