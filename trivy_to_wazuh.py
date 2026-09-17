#!/usr/bin/env python3
"""Convert Trivy CycloneDX JSON to JSONL for Wazuh log ingestion.
Each line is one vulnerability event, small enough for Wazuh's per-event limit."""

import json
import sys
from datetime import datetime, timezone

def convert(cdx_path, image_tag, output_path="/var/log/sbom/trivy-findings.jsonl"):
    with open(cdx_path, "r") as f:
        sbom = json.load(f)

    ref_map = {}
    for c in sbom.get("components", []):
        if c.get("bom-ref"):
            ref_map[c["bom-ref"]] = {
                "name": c.get("name"),
                "version": c.get("version"),
                "purl": c.get("purl"),
            }

    vulns = sbom.get("vulnerabilities", [])
    count = 0

    with open(output_path, "a") as out:
        for v in vulns:
            severity = "unknown"
            for r in v.get("ratings", []):
                severity = (r.get("severity") or "unknown").lower()
                break

            affects = v.get("affects") or [{}]
            for aff in affects:
                comp = ref_map.get(aff.get("ref"), {})
                event = {
                    "source": "trivy",
                    "image": image_tag,
                    "cve_id": v.get("id"),
                    "severity": severity,
                    "package_name": comp.get("name"),
                    "installed_version": comp.get("version"),
                    "purl": comp.get("purl"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                out.write(json.dumps(event) + "\n")
                count += 1

    print(f"Wrote {count} events to {output_path}")

if __name__ == "__main__":
    cdx_path = sys.argv[1]
    image_tag = sys.argv[2]
    convert(cdx_path, image_tag)
