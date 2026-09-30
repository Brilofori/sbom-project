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

Usage:
  python3 scan_registry.py              # one pass (use with the hourly timer)
  python3 scan_registry.py --dry-run    # list what would be scanned, pull nothing
  python3 scan_registry.py --loop       # stay running, one pass per hour
  python3 scan_registry.py --config other.json
"""

import argparse
import fcntl
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from pymongo import MongoClient, UpdateOne

HOSTNAME = socket.gethostname()
MONGO_URI = os.environ.get("SBOM_MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("SBOM_DB", "sweri_sbom")
WAZUH_JSONL = os.environ.get("SBOM_JSONL", "/var/log/sbom/trivy-findings.jsonl")
LOCK_PATH = "/tmp/sbom-scan-registry.lock"
OUT_DIR = "out/registry"
MAX_ATTEMPTS = 3          # give up on an image after this many failed passes
SCAN_TIMEOUT = 3600       # seconds; large images take a while
PULL_TIMEOUT = 3600
WRITE_BATCH = 400         # lines written before pausing, so the Wazuh agent buffer keeps up

# Use the same pinned Trivy as scan_all.py when it's available.
try:
    from scan_all import TRIVY_IMAGE  # noqa: F401
except Exception:
    TRIVY_IMAGE = os.environ.get("SBOM_TRIVY_IMAGE", "aquasec/trivy:latest")


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
    for line in r.stdout.splitlines():
        if "@" in line:
            return line.split("@", 1)[1].strip()
    return None


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


# ---------------------------------------------------------------- one pass

def one_pass(cfg, db, dry_run=False):
    registry = cfg.get("registry", "docker.io")
    platform = cfg.get("platform", "linux/amd64")
    done = db["registry_scans"]

    todo = []
    for entry in cfg["repositories"]:
        entry.setdefault("platform", platform)
        try:
            tags = list_tags(entry)
        except Exception as e:
            log(f"could not list {entry['repo']}: {e}")
            continue
        log(f"{entry['repo']}: {len(tags)} tag(s) in scope")
        for image, repo, tag, digest in tags:
            prev = done.find_one({"image": image, "digest": digest})
            if prev and prev.get("status") == "ok":
                continue
            if prev and prev.get("attempts", 0) >= MAX_ATTEMPTS:
                log(f"  giving up on {image} after {prev['attempts']} failures")
                continue
            todo.append((image, repo, tag, digest))

    log(f"{len(todo)} image(s) not yet scanned")
    if dry_run:
        for image, _, _, digest in todo:
            print(f"  would scan {image}  {digest[:19]}")
        return []

    results = []
    for n, (image, repo, tag, digest) in enumerate(todo, 1):
        log(f"[{n}/{len(todo)}] {image}")
        results.append(process(db, image, repo, tag, digest, registry, platform))
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
        sys.exit(f"MongoDB not reachable at {MONGO_URI}: {e}")
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
