#!/usr/bin/env python3
"""Scan container images with Trivy, track what changed in MongoDB, and hand only the
changes to Wazuh as JSON lines.

Usage:
    python3 scan_all.py                  scan every image on this host
    python3 scan_all.py inventory.txt    scan only the images listed (one per line, # comments ok)
    python3 scan_all.py --rebaseline     forget previous state and resend everything once

Per image: Trivy -> CycloneDX JSON (out/) -> compare with state in MongoDB -> append
changes to the Wazuh log -> commit state -> save the scan -> write out/report_<image>.md.
Events are written *before* state is committed, so a failed write is retried next run
instead of being lost.
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

from pymongo import UpdateOne
from pymongo.errors import DocumentTooLarge

import report
from sbom_common import OUT_DIR, PACKAGE_TYPES, get_db, identity, safe_name

HOSTNAME = socket.gethostname()

# Trivy 0.74.0, pinned by digest so every host runs the identical scanner (see README,
# "Trivy image"). Override with SBOM_TRIVY_IMAGE, e.g. for an internal registry mirror.
TRIVY_IMAGE = os.environ.get(
    "SBOM_TRIVY_IMAGE",
    "aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969",
)
# Named Docker volume for Trivy's DB cache, so the DB isn't re-downloaded for every image.
TRIVY_CACHE_VOLUME = os.environ.get("SBOM_TRIVY_CACHE", "trivy-cache")
WAZUH_JSONL = os.environ.get("SBOM_WAZUH_LOG", "/var/log/sbom/trivy-findings.jsonl")
# The Wazuh agent forwards 500 events/s by default and drops overflow; stay under it.
WAZUH_EPS = int(os.environ.get("SBOM_WAZUH_EPS", "400"))

TRIVY_REPOS = {"aquasec/trivy", "trivy", "ghcr.io/aquasecurity/trivy",
               "public.ecr.aws/aquasecurity/trivy"}
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
                 "none": 0, "unknown": 0}
_RECOMMENDATION = re.compile(r"^Upgrade (?P<pkg>.+?) to version (?P<ver>.+)$")


class ScanError(Exception):
    """Trivy failed for one image."""


# --------------------------------------------------------------------------- Trivy ---

def error_tail(stderr, n=12):
    """The useful end of Trivy's stderr: FATAL/ERROR lines if any, else the last lines.
    (The start is INFO chatter about DB downloads, which hides the real error.)"""
    lines = [line for line in (stderr or "").strip().splitlines() if line.strip()]
    errors = [line for line in lines if "FATAL" in line or "ERROR" in line]
    return "\n".join((errors or lines)[-n:])


def trivy_cmd(*args, mounts=()):
    cmd = ["docker", "run", "--rm", "-v", f"{TRIVY_CACHE_VOLUME}:/root/.cache/trivy"]
    for mount in mounts:
        cmd += ["-v", mount]
    return [*cmd, TRIVY_IMAGE, *args]


def prepare_trivy():
    """Download the vulnerability DB once, so every image in this run is scanned against
    the same DB. Returns (trivy_version, db_updated_at, db_ready)."""
    try:
        r = subprocess.run(trivy_cmd("image", "--download-db-only", "--no-progress"),
                           capture_output=True, text=True, timeout=1800)
        db_ready = r.returncode == 0
        problem = error_tail(r.stderr, 6)
    except subprocess.TimeoutExpired:
        db_ready, problem = False, "timed out after 30 minutes"
    if not db_ready:
        print("  warning: Trivy DB download failed; each scan will try to update it itself\n"
              f"  {problem}")

    version, db_updated = "unknown", None
    try:
        r = subprocess.run(trivy_cmd("version", "--format", "json"),
                           capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return version, db_updated, db_ready
    try:
        info = json.loads(r.stdout)
        version = info.get("Version") or "unknown"
        db_updated = (info.get("VulnerabilityDB") or {}).get("UpdatedAt")
    except (json.JSONDecodeError, AttributeError):
        for line in r.stdout.splitlines():
            if line.lower().startswith("version"):
                version = line.split(":", 1)[1].strip()
                break
    return version, db_updated, db_ready


def scan_image(image, out_dir, skip_db_update):
    """Run Trivy against one image; return the CycloneDX output path or raise ScanError.

    Trivy writes to a .partial file that replaces out/<image>.json only on success, so
    a failed scan never leaves a stale or half-written file, and the last good SBOM for
    the image is kept (export_cyclonedx.py uses it)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{safe_name(image)}.json"
    partial = out_dir / f"{safe_name(image)}.json.partial"
    partial.unlink(missing_ok=True)

    args = ["image", "--scanners", "vuln", "--format", "cyclonedx", "--timeout", "30m",
            "--no-progress", "--output", f"/out/{partial.name}"]
    if skip_db_update:
        args.append("--skip-db-update")
    cmd = trivy_cmd(*args, image, mounts=("/var/run/docker.sock:/var/run/docker.sock",
                                          f"{out_dir.resolve()}:/out"))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not partial.exists():
        partial.unlink(missing_ok=True)
        raise ScanError(error_tail(r.stderr) or f"Trivy exited {r.returncode} without output")
    os.replace(partial, out_path)
    return out_path


# ------------------------------------------------------------- CycloneDX parsing ---

def fixed_versions(vuln):
    """{package: fixed version} from Trivy's `recommendation`, the only place Trivy
    writes it, e.g. "Upgrade libssl3 to version 3.0.15-1~deb12u1; Upgrade openssl to ..."."""
    fixes = {}
    for part in (vuln.get("recommendation") or "").split("; "):
        m = _RECOMMENDATION.match(part.strip())
        if m:
            fixes[m["pkg"]] = m["ver"]
    return fixes


def fixed_version_for(fixes, comp, n_affected):
    """Match one affected component to its fix. Maven packages appear as group:name."""
    name, group = comp.get("name"), comp.get("group")
    for key in (name, f"{group}:{name}" if group else None, f"{group}/{name}" if group else None):
        if key and key in fixes:
            return fixes[key]
    if n_affected == 1 and len(fixes) == 1:
        return next(iter(fixes.values()))
    return None


def severities(vuln):
    """(trivy_severity, max_severity).

    trivy_severity follows Trivy's own rule: the rating from the vulnerability's data
    source (e.g. Debian for a Debian package), then GitHub for GHSA IDs, then NVD.
    max_severity is the worst rating from any source, including other distributions'
    ratings of their own builds; kept for anyone who wants the conservative view."""
    by_source, worst = {}, "unknown"
    for r in vuln.get("ratings") or []:
        src = (r.get("source") or {}).get("name")
        sev = (r.get("severity") or "unknown").lower()
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(worst, 0):
            worst = sev
        # Trivy re-derives NVD's CVSSv2 severity from the v2 score; its own NVD
        # severity is the one on the v3/v4 rating, so prefer those.
        if src not in by_source or r.get("method") != "CVSSv2":
            by_source[src] = sev
    order = [(vuln.get("source") or {}).get("name")]
    if (vuln.get("id") or "").startswith("GHSA-"):
        order.append("ghsa")
    order.append("nvd")
    trivy = next((by_source[s] for s in order if s in by_source), worst)
    return trivy, worst


def image_metadata(sbom):
    """Image ID, repo digests, OS and Trivy version that Trivy records in the BOM."""
    meta = sbom.get("metadata") or {}
    props = (meta.get("component") or {}).get("properties") or []

    def values(name):
        return [p.get("value") for p in props
                if p.get("name") == f"aquasecurity:trivy:{name}" and p.get("value")]

    tools = meta.get("tools") or {}
    tool_list = tools.get("components", []) if isinstance(tools, dict) else tools
    trivy = next((t.get("version") for t in tool_list if t.get("name") == "trivy"), None)
    os_comp = next((c for c in sbom.get("components") or []
                    if c.get("type") == "operating-system"), None)
    return {
        "image_id": next(iter(values("ImageID")), None),
        "repo_digests": values("RepoDigest"),
        "os": f"{os_comp.get('name')} {os_comp.get('version') or ''}".strip() if os_comp else None,
        "trivy_version": trivy,
    }


def parse_sbom(sbom):
    """Return (components, flat_vulns, cve_info). One flat vuln per (CVE, affected package)."""
    components = sbom.get("components") or []
    by_ref = {c["bom-ref"]: c for c in components if c.get("bom-ref")}
    flat_vulns, cve_info = [], {}
    for v in sbom.get("vulnerabilities") or []:
        cve = v.get("id")
        trivy_sev, max_sev = severities(v)
        fixes = fixed_versions(v)
        affects = v.get("affects") or [{}]
        if cve:
            cve_info[cve] = {"description": v.get("description"), "published": v.get("published"),
                             "updated": v.get("updated"), "source": (v.get("source") or {}).get("name")}
        for aff in affects:
            comp = by_ref.get(aff.get("ref"), {})
            flat_vulns.append({
                "cve_id": cve,
                "severity": trivy_sev,
                "max_severity": max_sev,
                "package_name": comp.get("name"),
                "installed_version": comp.get("version"),
                "fixed_version": fixed_version_for(fixes, comp, len(affects)),
                "purl": comp.get("purl"),
                "identity": identity(comp.get("purl"), comp.get("type"), comp.get("name")),
            })
    return components, flat_vulns, cve_info


# ------------------------------------------------------------------ change tracking ---

def track_changes(db, host, image, components, flat_vulns, image_id, now):
    """Compare this scan with stored state. Returns (events, component_ops, vuln_ops,
    counts, resolved) and marks each flat vuln with is_new/first_seen/cause. Nothing is
    written to MongoDB here.

    State is keyed on (host, image, package identity), not on the purl, so a version
    bump or an OS point release shows up as one "component_changed" event instead of
    every package and CVE looking new."""
    key = {"host": host, "image": image}
    comp_docs = {d["identity"]: d for d in db["component_state"].find(key)}
    vuln_docs = {(d["cve_id"], d["identity"]): d for d in db["vuln_state"].find(key)}
    baseline = not comp_docs and not vuln_docs

    prev = db["scans"].find_one(key, sort=[("scanned_at", -1)], projection={"image_id": 1})
    prev_image_id = (prev or {}).get("image_id")
    if baseline:
        cause = "baseline"
    elif image_id and prev_image_id:
        # Same image ID: nothing in the image changed, so a new CVE came from updated
        # vulnerability data. Different ID: the image itself was rebuilt or retagged.
        cause = "db_update" if image_id == prev_image_id else "image_changed"
    else:
        cause = "unknown"

    base = {"source": "trivy", "host": host, "image": image, "image_id": image_id}
    events, comp_ops, vuln_ops = [], [], []
    counts = {"packages": 0, "added": 0, "changed": 0, "removed": 0, "new_vulns": 0, "resolved": 0}

    # ---- components
    current = {}
    for c in components:
        if c.get("type") not in PACKAGE_TYPES or not c.get("name"):
            continue
        ident = identity(c.get("purl"), c.get("type"), c.get("name"))
        entry = current.setdefault(ident, {"name": c["name"], "type": c.get("type"),
                                           "purl": c.get("purl"), "versions": set()})
        entry["versions"].add(c.get("version") or "")
    counts["packages"] = len(current)

    for ident, cur in current.items():
        versions = sorted(cur["versions"])
        doc = comp_docs.get(ident)
        event = {**base, "identity": ident, "package_name": cur["name"],
                 "package_type": cur["type"], "installed_version": ", ".join(versions),
                 "purl": cur["purl"]}
        if doc is None or not doc.get("present"):
            events.append({**event, "sbom_event": "component",
                           "cause": "baseline" if baseline else ("re-added" if doc else "added")})
            counts["added"] += 1
        elif doc.get("versions") != versions:
            events.append({**event, "sbom_event": "component_changed",
                           "previous_version": ", ".join(doc.get("versions") or [])})
            counts["changed"] += 1
        comp_ops.append(UpdateOne(
            {**key, "identity": ident},
            {"$set": {"name": cur["name"], "type": cur["type"], "purl": cur["purl"],
                      "versions": versions, "present": True, "last_seen": now,
                      "removed_at": None},
             "$setOnInsert": {"first_seen": now}},
            upsert=True))

    for ident, doc in comp_docs.items():
        if doc.get("present") and ident not in current:
            events.append({**base, "sbom_event": "component_removed", "identity": ident,
                           "package_name": doc.get("name"), "package_type": doc.get("type"),
                           "previous_version": ", ".join(doc.get("versions") or [])})
            counts["removed"] += 1
            comp_ops.append(UpdateOne({**key, "identity": ident},
                                      {"$set": {"present": False, "removed_at": now}}))

    # ---- vulnerabilities (one entry per CVE + package identity)
    current_v = {}
    for fv in flat_vulns:
        k = (fv["cve_id"], fv["identity"])
        if k not in current_v:
            current_v[k] = dict(fv)
        elif fv.get("installed_version"):  # several installed copies of the same package
            seen = (current_v[k].get("installed_version") or "").split(", ")
            if fv["installed_version"] not in seen:
                current_v[k]["installed_version"] = ", ".join(
                    [x for x in seen if x] + [fv["installed_version"]])

    new_keys = set()
    for (cve, ident), fv in current_v.items():
        doc = vuln_docs.get((cve, ident))
        is_new = doc is None or doc.get("status") != "open"
        fields = {"package_name": fv["package_name"], "installed_version": fv["installed_version"],
                  "fixed_version": fv["fixed_version"], "severity": fv["severity"],
                  "max_severity": fv["max_severity"], "status": "open", "last_seen": now,
                  "resolved_at": None}
        if is_new:
            new_keys.add((cve, ident))
            fields["opened_at"] = now
            events.append({**base, "sbom_event": "vulnerability", "cve_id": cve,
                           "identity": ident, "severity": fv["severity"],
                           "max_severity": fv["max_severity"],
                           "package_name": fv["package_name"],
                           "installed_version": fv["installed_version"],
                           "fixed_version": fv["fixed_version"], "purl": fv["purl"],
                           "cause": "regression" if doc is not None else cause})
            counts["new_vulns"] += 1
        vuln_ops.append(UpdateOne({**key, "cve_id": cve, "identity": ident},
                                  {"$set": fields, "$setOnInsert": {"first_seen": now}},
                                  upsert=True))

    resolved = []
    for (cve, ident), doc in vuln_docs.items():
        if doc.get("status") == "open" and (cve, ident) not in current_v:
            item = {"cve_id": cve, "identity": ident, "package_name": doc.get("package_name"),
                    "severity": doc.get("severity"),
                    "installed_version": doc.get("installed_version")}
            resolved.append(item)
            events.append({**base, "sbom_event": "vulnerability_resolved", **item})
            counts["resolved"] += 1
            vuln_ops.append(UpdateOne({**key, "cve_id": cve, "identity": ident},
                                      {"$set": {"status": "resolved", "resolved_at": now}}))

    first_seen = {k: d.get("first_seen") for k, d in vuln_docs.items()}
    for fv in flat_vulns:
        k = (fv["cve_id"], fv["identity"])
        fv["is_new"] = k in new_keys
        fv["first_seen"] = now if fv["is_new"] else first_seen.get(k, now)
        if fv["is_new"]:
            fv["cause"] = "regression" if k in vuln_docs else cause
    return events, comp_ops, vuln_ops, counts, resolved


def deliver(events, path=None, eps=None):
    """Append events to the log the Wazuh agent reads. Raises OSError on failure, so the
    caller doesn't commit state for events that were never written."""
    if not events:
        return 0
    path = path or WAZUH_JSONL
    eps = WAZUH_EPS if eps is None else eps
    ts = datetime.now(timezone.utc).isoformat()
    with open(path, "a", encoding="utf-8") as out:
        for i, event in enumerate(events, 1):
            out.write(json.dumps({**event, "timestamp": ts}, default=str) + "\n")
            if eps and i % eps == 0 and i < len(events):
                out.flush()
                time.sleep(1)  # let the agent drain before the next batch
        out.flush()
        os.fsync(out.fileno())
    return len(events)


def ingest(db, image, sbom_path, host=None, scanner_version=None, db_updated=None,
           wazuh_log=None, eps=None, now=None):
    """Parse one Trivy CycloneDX file, deliver changes to Wazuh, then commit state and
    save the scan. Returns a summary dict."""
    host = host or HOSTNAME
    now = now or datetime.now(timezone.utc)
    with open(sbom_path, encoding="utf-8") as f:
        sbom = json.load(f)

    meta = image_metadata(sbom)
    components, flat_vulns, cve_info = parse_sbom(sbom)
    events, comp_ops, vuln_ops, counts, resolved = track_changes(
        db, host, image, components, flat_vulns, meta["image_id"], now)

    sent = deliver(events, wazuh_log, eps)  # 1. deliver (raises if the log isn't writable)
    if comp_ops:                             # 2. then commit state
        db["component_state"].bulk_write(comp_ops, ordered=False)
    if vuln_ops:
        db["vuln_state"].bulk_write(vuln_ops, ordered=False)

    doc = {                                  # 3. then keep the scan for reports
        "host": host,
        "image": image,
        "scanned_at": now,
        "source_file": str(sbom_path),
        "scanner": "trivy",
        "scanner_version": meta["trivy_version"] or scanner_version,
        "db_updated_at": db_updated,
        "image_id": meta["image_id"],
        "repo_digests": meta["repo_digests"],
        "os": meta["os"],
        "component_count": len(components),
        "vulnerability_count": len(flat_vulns),
        "new_vulnerability_count": counts["new_vulns"],
        "resolved_vulnerability_count": counts["resolved"],
        "new_component_count": counts["added"],
        "changed_component_count": counts["changed"],
        "removed_component_count": counts["removed"],
        "components": [{"name": c.get("name"), "version": c.get("version"),
                        "type": c.get("type"), "purl": c.get("purl")} for c in components],
        "vulnerabilities": flat_vulns,
        "resolved": resolved,
    }
    try:
        db["scans"].insert_one(doc)
    except DocumentTooLarge:  # >16MB: keep the summary and components, drop the per-CVE list
        doc.pop("_id", None)
        doc.update(vulnerabilities=[], truncated=True)
        db["scans"].insert_one(doc)

    info_ops = [UpdateOne({"cve_id": cve}, {"$set": {**info, "last_seen": now}}, upsert=True)
                for cve, info in cve_info.items()]
    if info_ops:
        db["cve_info"].bulk_write(info_ops, ordered=False)

    return {"image": image, "components": len(components), "vulnerabilities": len(flat_vulns),
            "sent": sent, **counts}


# ----------------------------------------------------------------------- DB setup ---

def _move_aside(db, name, suffix):
    if name not in db.list_collection_names():
        return None
    target = f"{name}_{suffix}"
    if target in db.list_collection_names():
        target = f"{target}_{datetime.now(timezone.utc):%Y%m%d%H%M%S}"
    db[name].rename(target)
    return target


_LEGACY_KEY_FIELD = {"vuln_state": "purl", "component_state": "comp_key"}


def _is_legacy(coll, key_field):
    if coll.find_one({"identity": {"$exists": False}}) is not None:
        return True
    # an old unique index left on an empty collection would reject the new documents
    return any(key_field in [k for k, _ in spec.get("key", [])]
               for spec in coll.index_information().values())


def migrate_legacy_state(db):
    """State written before Sept 2026 was keyed on the full purl. Move it aside (it is
    kept, not deleted) so this version starts clean. The next run re-sends the current
    inventory to Wazuh once."""
    moved = []
    for name, key_field in _LEGACY_KEY_FIELD.items():
        if name in db.list_collection_names() and _is_legacy(db[name], key_field):
            moved.append(_move_aside(db, name, "legacy"))
    return [m for m in moved if m]


def rebaseline(db):
    stamp = f"before_rebaseline_{datetime.now(timezone.utc):%Y%m%d%H%M%S}"
    return [m for m in (_move_aside(db, "vuln_state", stamp),
                        _move_aside(db, "component_state", stamp)) if m]


def ensure_indexes(db):
    db["component_state"].create_index([("host", 1), ("image", 1), ("identity", 1)], unique=True)
    db["vuln_state"].create_index([("host", 1), ("image", 1), ("cve_id", 1), ("identity", 1)],
                                  unique=True)
    db["scans"].create_index([("host", 1), ("image", 1), ("scanned_at", -1)])
    db["cve_info"].create_index("cve_id", unique=True)


# ------------------------------------------------------------------------- inputs ---

def read_inventory(path):
    images = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            image = raw.split("#", 1)[0].strip()
            if image:
                images.append(image)
    return list(dict.fromkeys(images))  # de-duplicate, keep order


def discover_images():
    """Every tagged image on this host (running or not), except Trivy itself."""
    try:
        r = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                           capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("docker not found on PATH")
    if r.returncode != 0:
        sys.exit(f"'docker images' failed: {error_tail(r.stderr, 4)}\n"
                 "Is Docker running, and is this user in the docker group?")
    images = set()
    for raw in r.stdout.splitlines():
        ref = raw.strip()
        if not ref or "<none>" in ref:
            continue
        if ref.rsplit(":", 1)[0] in TRIVY_REPOS:
            continue
        images.add(ref)
    return sorted(images)


def check_wazuh_log(path):
    """Fail before scanning if the Wazuh log can't be written."""
    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, exist_ok=True)
        with open(path, "a", encoding="utf-8"):
            pass
    except OSError as e:
        sys.exit(f"Cannot write the Wazuh log {path}: {e}\n"
                 f"Fix: sudo mkdir -p {directory} && sudo chown -R $USER {directory}")


def check_out_dir(out_dir):
    """Fail before scanning if out/ isn't writable (e.g. created by root via Docker)."""
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        probe = out_dir / ".write-test"
        probe.write_text("")
        probe.unlink()
    except OSError as e:
        sys.exit(f"Cannot write to {out_dir}: {e}\nFix: sudo chown -R $USER {out_dir}")


def acquire_lock(out_dir):
    """Stop two runs (cron + manual) from racing on the same state."""
    try:
        import fcntl
    except ImportError:  # not on Linux; skip locking
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    handle = open(out_dir / ".scan.lock", "w")  # held open for the whole run
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit("Another scan_all.py run is already in progress")
    return handle


# --------------------------------------------------------------------------- main ---

def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan images with Trivy and track changes.")
    ap.add_argument("inventory", nargs="?",
                    help="file with one image per line (default: every image on this host)")
    ap.add_argument("--rebaseline", action="store_true",
                    help="set current state aside and resend the full inventory to Wazuh")
    args = ap.parse_args(argv)

    if args.inventory:
        if not os.path.isfile(args.inventory):
            sys.exit(f"Inventory file not found: {args.inventory}")
        images, source = read_inventory(args.inventory), f"inventory file {args.inventory}"
    else:
        images, source = discover_images(), "host image discovery"
    if not images:
        sys.exit("No images found to scan")

    check_out_dir(OUT_DIR)
    lock = acquire_lock(OUT_DIR)  # noqa: F841 (held until exit)
    check_wazuh_log(WAZUH_JSONL)
    db = get_db()
    moved = migrate_legacy_state(db)
    if args.rebaseline:
        moved += rebaseline(db)
    ensure_indexes(db)

    run_time = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    version, db_updated, db_ready = prepare_trivy()
    print(f"\nSBOM pipeline  {run_time}")
    print(f"host {HOSTNAME}  |  trivy {version}  |  DB {db_updated or 'unknown'}  |  "
          f"{len(images)} images via {source}")
    if moved:
        print(f"  previous state moved to {', '.join(moved)}: this run re-sends the full "
              "inventory to Wazuh once")

    results = []
    for image in images:
        print(f"\n  scanning  {image}")
        try:
            sbom_path = scan_image(image, OUT_DIR, skip_db_update=db_ready)
            r = ingest(db, image, sbom_path, scanner_version=version, db_updated=db_updated)
        except ScanError as e:
            print("     scan failed:\n     " + str(e).replace("\n", "\n     "))
            results.append({"image": image, "error": "scan failed"})
            continue
        except Exception as e:  # keep going with the other images; state was not committed
            print(f"     failed: {type(e).__name__}: {e}")
            results.append({"image": image, "error": type(e).__name__})
            continue
        try:
            report.write_report(db, image, OUT_DIR / f"report_{safe_name(image)}.md", host=HOSTNAME)
        except Exception as e:
            print(f"     report not written: {type(e).__name__}: {e}")
        results.append(r)
        print(f"     {r['packages']} packages ({r['added']} new, {r['changed']} changed, "
              f"{r['removed']} removed)  |  {r['vulnerabilities']} vulns ({r['new_vulns']} new, "
              f"{r['resolved']} resolved)  |  {r['sent']} events to wazuh")

    failed = [r for r in results if "error" in r]
    print(f"\ncomplete  {HOSTNAME}  ({len(results) - len(failed)} ok, {len(failed)} failed)")
    for r in results:
        if "error" in r:
            print(f"  x  {r['image']}  {r['error']}")
        else:
            flag = "  *" if r["sent"] else "   "
            print(f"{flag} {r['image']}  {r['packages']} pkg, {r['vulnerabilities']} vuln  "
                  f"(+{r['new_vulns']} vuln, -{r['resolved']} resolved, "
                  f"{r['added']}/{r['changed']}/{r['removed']} pkg added/changed/removed)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
