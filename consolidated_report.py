#!/usr/bin/env python3
"""Consolidated package-centric inventory across all scans.
Answers: which package, which versions, which images, which hosts."""

import sys
from collections import defaultdict
from datetime import datetime, timezone
from pymongo import MongoClient

def build_report(out_path="out/consolidated_inventory.md"):
    db = MongoClient("mongodb://localhost:27017")["sweri_sbom"]

    # For each image, use only its most recent scan
    latest = {}
    for scan in db["scans"].find().sort("scanned_at", 1):
        latest[scan["image"]] = scan  # later scans overwrite earlier

    # package name -> version -> set of (image, host)
    packages = defaultdict(lambda: defaultdict(set))
    hosts = set()
    image_count = 0

    for image, scan in latest.items():
        host = scan.get("host", "unknown")
        hosts.add(host)
        image_count += 1
        for c in scan.get("components", []):
            name = c.get("name")
            version = c.get("version") or "unknown"
            if name:
                packages[name][version].add((image, host))

    lines = []
    lines.append("# Consolidated Package Inventory")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')}")
    lines.append(f"**Images:** {image_count}")
    lines.append(f"**Hosts:** {', '.join(sorted(hosts))}")
    lines.append(f"**Unique packages:** {len(packages)}")
    lines.append("")

    # Packages that exist in more than one version = the "which is good, which is bad" problem
    multi_version = {n: v for n, v in packages.items() if len(v) > 1}
    if multi_version:
        lines.append(f"## Packages With Multiple Versions Present ({len(multi_version)})")
        lines.append("")
        lines.append("These are the same package existing at different versions across the "
                     "environment, the case worth reviewing first.")
        lines.append("")
        for name in sorted(multi_version):
            versions = multi_version[name]
            lines.append(f"**{name}**")
            for version in sorted(versions):
                locations = sorted(versions[version])
                loc_str = ", ".join(f"{img} on {host}" for img, host in locations)
                lines.append(f"- `{version}` — {loc_str}")
            lines.append("")

    lines.append("## Full Package Inventory")
    lines.append("")
    lines.append("| Package | Version | Image | Host |")
    lines.append("|---------|---------|-------|------|")
    for name in sorted(packages):
        for version in sorted(packages[name]):
            for image, host in sorted(packages[name][version]):
                lines.append(f"| {name} | {version} | {image} | {host} |")

    lines.append("")
    lines.append("---")
    lines.append(f"*Generated from {image_count} images across {len(hosts)} host(s)*")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Consolidated inventory written to {out_path}")
    print(f"  {len(packages)} unique packages across {image_count} images")
    print(f"  {len(multi_version)} packages have multiple versions present")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "out/consolidated_inventory.md"
    build_report(out)
