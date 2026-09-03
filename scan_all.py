import json
import subprocess
import sys
import os
from datetime import datetime, timezone
from pymongo import MongoClient

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

def scan_image(image, out_dir):
    """Run Trivy against one image, return the output path."""
    os.makedirs(out_dir, exist_ok=True)
    safe_name = image.replace("/", "_").replace(":", "_")
    out_path = os.path.join(out_dir, f"{safe_name}.json")

    print(f"\n{'='*60}")
    print(f"Scanning: {image}")
    print(f"{'='*60}")

    cmd = [
        "docker", "run", "--rm",
        "-v", "//var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{os.getcwd().replace(os.sep, '/')}/{out_dir}:/out",
        "aquasec/trivy", "image",
        "--scanners", "vuln",
        "--format", "cyclonedx",
        "--output", f"/out/{safe_name}.json",
        image,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  SCAN FAILED: {result.stderr[:300]}")
        return None

    if not os.path.exists(out_path):
        print(f"  OUTPUT MISSING: {out_path}")
        return None

    print(f"  Output: {out_path}")
    return out_path

def ingest_scan(filepath, image_tag, db):
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
        "image": image_tag,
        "scanned_at": scanned_at,
        "source_file": filepath,
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

    result = db["scans"].insert_one(doc)
    return {
        "image": image_tag,
        "scan_id": str(result.inserted_id),
        "components": len(components),
        "vulnerabilities": len(flat_vulns),
        "new": len(new_findings),
        "new_findings": new_findings,
    }

def generate_report(image_tag, db, out_dir):
    """Generate markdown vulnerability summary."""
    scan = db["scans"].find_one(
        {"image": image_tag},
        sort=[("scanned_at", -1)]
    )
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
    lines.append(f"**Components:** {scan.get('component_count', len(components))}")
    lines.append(f"**Total vulnerabilities:** {len(vulns)}")
    lines.append(f"**New since last scan:** {scan.get('new_vulnerability_count', len(new_findings))}")
    lines.append(f"**With fix available:** {len(fixable)}")
    lines.append(f"**Critical + High:** {len(actionable)}")
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

    print(f"  Report: {report_path}")

def main():
    inventory_file = sys.argv[1] if len(sys.argv) > 1 else "inventory.txt"
    out_dir = "out"

    if not os.path.exists(inventory_file):
        print(f"Inventory file not found: {inventory_file}")
        sys.exit(1)

    with open(inventory_file, "r") as f:
        images = [line.strip() for line in f if line.strip()]

    if not images:
        print("No images in inventory file")
        sys.exit(1)

    print(f"SBOM Pipeline Run: {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')}")
    print(f"Images to scan: {len(images)}")

    client = MongoClient("mongodb://localhost:27017")
    db = client["sweri_sbom"]

    results = []
    for image in images:
        out_path = scan_image(image, out_dir)
        if out_path:
            result = ingest_scan(out_path, image, db)
            results.append(result)
            print(f"  Components: {result['components']}")
            print(f"  Vulnerabilities: {result['vulnerabilities']}")
            print(f"  NEW: {result['new']}")
            generate_report(image, db, out_dir)
        else:
            results.append({"image": image, "error": "scan failed"})

    print(f"\n{'='*60}")
    print("PIPELINE COMPLETE")
    print(f"{'='*60}")
    for r in results:
        if "error" in r:
            print(f"  FAILED: {r['image']}")
        else:
            status = "NEW FINDINGS" if r["new"] > 0 else "no changes"
            print(f"  {r['image']}: {r['vulnerabilities']} vulns, "
                  f"{r['new']} new ({status})")

if __name__ == "__main__":
    main()