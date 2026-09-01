import json
import sys
from datetime import datetime, timezone
from pymongo import MongoClient

SEVERITY_RANK = {
    "critical": 5, "high": 4, "medium": 3,
    "low": 2, "info": 1, "none": 0, "unknown": 0,
}

def highest_severity(ratings):
    """Trivy often supplies several ratings from different sources.
    Take the highest so alerting never under-reports."""
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

def ingest(filepath, image_tag):
    with open(filepath, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    components = sbom.get("components", [])
    vulnerabilities = sbom.get("vulnerabilities", [])
    scanned_at = datetime.now(timezone.utc)

    # bom-ref -> component, so CVEs can be linked back to a package
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

    client = MongoClient("mongodb://localhost:27017")
    db = client["sweri_sbom"]
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
    print(f"Inserted scan for {image_tag}: {result.inserted_id}")
    print(f"  components: {len(components)}")
    print(f"  vulnerabilities: {len(flat_vulns)}")
    print(f"  NEW since last scan: {len(new_findings)}")
    for f in new_findings[:10]:
        print(f"    [{f['severity'].upper()}] {f['cve_id']} - "
              f"{f['package_name']} {f['installed_version']}")

if __name__ == "__main__":
    ingest(sys.argv[1], sys.argv[2])