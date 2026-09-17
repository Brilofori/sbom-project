import json
import subprocess
import sys
import os
from datetime import datetime, timezone
from pymongo import MongoClient
import socket

HOSTNAME = socket.gethostname()
TRIVY_IMAGE = "trivy:sweri"
WAZUH_JSONL = "/var/log/sbom/trivy-findings.jsonl"

SEVERITY_RANK = {
    "critical": 5, "high": 4, "medium": 3,
    "low": 2, "info": 1, "none": 0, "unknown": 0,
}

def highest_severity(ratings):
    best, best_rank = "unknown", -1
    for r in ratings or []:
        sev = (r.get("severity") or "unknown").lower()
        rank = SEVERITY_RANK.get(sev, 0)
        if rank > best_rank:
            best, best_rank = sev, rank
    return best

def extract_fixed_version(vuln):
    for aff in vuln.get("affects", []):
        for v in aff.get("versions", []):
            if v.get("status") == "unaffected" and v.get("version"):
                return v["version"]
    for p in vuln.get("properties", []):
        if "fixed" in (p.get("name") or "").lower():
            return p.get("value")
    return None

def trivy_version():
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", TRIVY_IMAGE, "--version"],
            capture_output=True, text=True
        )
        for line in r.stdout.splitlines():
            if line.lower().startswith("version"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"

def scan_image(image, out_dir):
    """Run Trivy against one image, return the output path."""
    os.makedirs(out_dir, exist_ok=True)
    safe_name = image.replace("/", "_").replace(":", "_")
    out_path = os.path.join(out_dir, f"{safe_name}.json")

    print(f"\n  scanning  {image}")

    cmd = [
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{os.path.abspath(out_dir)}:/out",
        TRIVY_IMAGE, "image",
        "--scanners", "vuln",
        "--format", "cyclonedx",
        "--timeout", "30m",
        "--output", f"/out/{safe_name}.json",
        image,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"     scan failed: {result.stderr.strip()[:200]}")
        return None

    if not os.path.exists(out_path):
        print(f"     output missing")
        return None

    return out_path

def ingest_scan(filepath, image_tag, db, scanner_version):
    """Parse CycloneDX and store in MongoDB."""
    with open(filepath, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    components = sbom.get("components", [])
    vulnerabilities = sbom.get("vulnerabilities", [])
    scanned_at = datetime.now(timezone.utc)

    ref_map = {
        c["bom-ref"]: {
            "name": c.get("name"),
            "version": c.get("version"),
            "purl": c.get("purl"),
        }
        for c in components if c.get("bom-ref")
    }

    flat_vulns = []
    for v in vulnerabilities:
        base = {
            "cve_id": v.get("id"),
            "severity": highest_severity(v.get("ratings")),
            "fixed_version": extract_fixed_version(v),
            "description": v.get("description"),
        }
        affects = v.get("affects") or [{}]
        for aff in affects:
            comp = ref_map.get(aff.get("ref"), {})
            flat_vulns.append({
                **base,
                "package_name": comp.get("name"),
                "installed_version": comp.get("version"),
                "purl": comp.get("purl"),
            })

    db["vuln_state"].create_index(
        [("image", 1), ("cve_id", 1), ("purl", 1)], unique=True
    )

    new_findings = []
    for fv in flat_vulns:
        key = {"image": image_tag, "cve_id": fv["cve_id"], "purl": fv["purl"]}
        existing = db["vuln_state"].find_one(key)
        if existing is None:
            db["vuln_state"].insert_one({
                **key,
                "first_seen": scanned_at,
                "severity": fv["severity"],
                "package_name": fv["package_name"],
            })
            fv["is_new"] = True
            fv["first_seen"] = scanned_at
            new_findings.append(fv)
        else:
            fv["is_new"] = False
            fv["first_seen"] = existing["first_seen"]

    doc = {
        "host": HOSTNAME,
        "image": image_tag,
        "scanned_at": scanned_at,
        "source_file": filepath,
        "scanner": "trivy",
        "scanner_version": scanner_version,
        "component_count": len(components),
        "vulnerability_count": len(flat_vulns),
        "new_vulnerability_count": len(new_findings),
        "components": [
            {
                "name": c.get("name"),
                "version": c.get("version"),
                "type": c.get("type"),
                "purl": c.get("purl"),
            }
            for c in components
        ],
        "vulnerabilities": flat_vulns,
    }

    db["scans"].insert_one(doc)
    return {
        "image": image_tag,
        "components": len(components),
        "vulnerabilities": len(flat_vulns),
        "new": len(new_findings),
        "new_findings": new_findings,
    }

def write_wazuh_events(result, image_tag):
    """Append only NEW findings to the Wazuh log, so we never re-flood the agent."""
    new = result.get("new_findings", [])
    if not new:
        return 0
    os.makedirs(os.path.dirname(WAZUH_JSONL), exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    written = 0
    try:
        with open(WAZUH_JSONL, "a") as out:
            for fv in new:
                event = {
                    "source": "trivy",
                    "host": HOSTNAME,
                    "image": image_tag,
                    "cve_id": fv.get("cve_id"),
                    "severity": fv.get("severity"),
                    "package_name": fv.get("package_name"),
                    "installed_version": fv.get("installed_version"),
                    "fixed_version": fv.get("fixed_version"),
                    "purl": fv.get("purl"),
                    "timestamp": ts,
                }
                out.write(json.dumps(event) + "\n")
                written += 1
    except PermissionError:
        print(f"     wazuh log not writable ({WAZUH_JSONL})")
    return written

def generate_report(image_tag, db, out_dir):
    """Generate markdown vulnerability summary."""
    scan = db["scans"].find_one({"image": image_tag}, sort=[("scanned_at", -1)])
    if not scan:
        return

    vulns = scan.get("vulnerabilities", [])
    components = scan.get("components", [])

    severity_counts = {}
    for v in vulns:
        sev = (v.get("severity") or "unknown").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    fixable = [v for v in vulns if v.get("fixed_version")]
    new_findings = [v for v in vulns if v.get("is_new")]
    actionable = [v for v in vulns
                  if (v.get("severity") or "").lower() in ("critical", "high")]

    safe_name = image_tag.replace("/", "_").replace(":", "_")
    report_path = os.path.join(out_dir, f"report_{safe_name}.md")

    lines = []
    lines.append(f"# Vulnerability Summary: {image_tag}")
    lines.append("")
    lines.append(f"**Scan date:** {scan['scanned_at'].strftime('%d %B %Y, %H:%M UTC')}")
    lines.append(f"**Scanner:** trivy {scan.get('scanner_version', 'unknown')}")
    lines.append(f"**Host:** {scan.get('host', 'unknown')}")
    lines.append(f"**Components:** {scan.get('component_count', len(components))}")
    lines.append(f"**Total vulnerabilities:** {len(vulns)}")
    lines.append(f"**New since last scan:** {scan.get('new_vulnerability_count', len(new_findings))}")
    lines.append(f"**With fix available:** {len(fixable)}")
    lines.append(f"**Critical + High:** {len(actionable)}")
    lines.append("")

    if components and not vulns:
        lines.append("> Note: components inventoried but no vulnerabilities returned. "
                     "If this is an ML image, Conda-installed Python packages are not "
                     "detected by Trivy and may be missing from the inventory.")
        lines.append("")

    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev} | {count} |")
    lines.append("")

    if new_findings:
        lines.append("## New Findings This Scan")
        lines.append("")
        for v in new_findings[:20]:
            lines.append(
                f"- **[{(v.get('severity') or 'unknown').upper()}]** "
                f"{v.get('cve_id')} in {v.get('package_name')} "
                f"{v.get('installed_version', '')}"
            )
        if len(new_findings) > 20:
            lines.append(f"- ... and {len(new_findings) - 20} more")
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')}*")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def discover_images():
    """List all images present on this host (not just running ones)."""
    cmd = ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    images = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or "<none>" in line:
            continue
        if line.startswith(("trivy", "aquasec/trivy", "mongo")):
            continue  # skip tooling images
        images.append(line)
    return sorted(set(images))

def main():
    out_dir = "out"

    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        with open(sys.argv[1]) as f:
            images = [l.strip() for l in f if l.strip()]
        source = f"inventory file {sys.argv[1]}"
    else:
        images = discover_images()
        source = "host image discovery"

    if not images:
        print("No images found to scan")
        sys.exit(1)

    run_time = datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')
    scanner_version = trivy_version()

    print(f"\nSBOM pipeline  {run_time}")
    print(f"host {HOSTNAME}  |  trivy {scanner_version}  |  {len(images)} images via {source}")

    client = MongoClient("mongodb://localhost:27017")
    db = client["sweri_sbom"]

    results = []
    for image in images:
        out_path = scan_image(image, out_dir)
        if out_path:
            result = ingest_scan(out_path, image, db, scanner_version)
            sent = write_wazuh_events(result, image)
            generate_report(image, db, out_dir)
            result["wazuh_sent"] = sent
            results.append(result)
            print(f"     {result['components']} components  |  "
                  f"{result['vulnerabilities']} vulns  |  "
                  f"{result['new']} new  |  {sent} to wazuh")
        else:
            results.append({"image": image, "error": "scan failed"})

    print(f"\ncomplete  {HOSTNAME}")
    for r in results:
        if "error" in r:
            print(f"  x  {r['image']}  failed")
        else:
            flag = "  *" if r["new"] > 0 else "   "
            print(f"{flag} {r['image']}  {r['components']} comp, "
                  f"{r['vulnerabilities']} vuln, {r['new']} new")

if __name__ == "__main__":
    main()
