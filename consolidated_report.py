#!/usr/bin/env python3
"""Package-centric inventory across the latest scan of every image on every host.
Answers: which package, which versions, which images, which hosts.

Usage:
    python3 consolidated_report.py [OUTPUT.md]      default: out/consolidated_inventory.md

For the same inventory as a single CycloneDX SBOM file, use export_cyclonedx.py.
"""
import sys
from collections import defaultdict
from datetime import datetime, timezone

from sbom_common import OUT_DIR, PACKAGE_TYPES, get_db, latest_scans


def build_report(scans):
    # package name -> version -> {(image, host)}
    packages = defaultdict(lambda: defaultdict(set))
    hosts, images = set(), set()
    for scan in scans:
        host = scan.get("host") or "unknown"
        hosts.add(host)
        images.add((scan["image"], host))
        for c in scan.get("components") or []:
            if c.get("type") not in PACKAGE_TYPES or not c.get("name"):
                continue
            packages[c["name"]][c.get("version") or "unknown"].add((scan["image"], host))

    lines = [
        "# Consolidated Package Inventory",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')}",
        f"**Images:** {len(images)} (latest scan of each image on each host)",
        f"**Hosts:** {', '.join(sorted(hosts)) or 'none'}",
        f"**Unique packages:** {len(packages)}",
        "",
        "> Coverage: OS packages plus the language packages Trivy can read. Conda packages in "
        "an image's base environment are not inventoried, so ML images may be missing their "
        "Conda layer (see README, Known limitations).",
        "",
    ]

    # the same package at more than one version: the "which is good, which is bad" question
    multi_version = {n: v for n, v in packages.items() if len(v) > 1}
    if multi_version:
        lines += [f"## Packages With Multiple Versions Present ({len(multi_version)})", "",
                  "These are the same package at different versions across the environment, "
                  "the case worth reviewing first.", ""]
        for name in sorted(multi_version):
            lines.append(f"**{name}**")
            for version in sorted(multi_version[name]):
                where = ", ".join(f"{img} on {host}" for img, host in sorted(multi_version[name][version]))
                lines.append(f"- `{version}` — {where}")
            lines.append("")

    lines += ["## Full Package Inventory", "",
              "| Package | Version | Image | Host |", "|---------|---------|-------|------|"]
    for name in sorted(packages):
        for version in sorted(packages[name]):
            for image, host in sorted(packages[name][version]):
                lines.append(f"| {name} | {version} | {image} | {host} |")
    lines += ["", "---", f"*Generated from {len(images)} images across {len(hosts)} host(s)*", ""]
    return "\n".join(lines), len(packages), len(images), len(multi_version)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    out_path = argv[0] if argv else str(OUT_DIR / "consolidated_inventory.md")
    text, n_packages, n_images, n_multi = build_report(latest_scans(get_db()))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Consolidated inventory written to {out_path}")
    print(f"  {n_packages} unique packages across {n_images} images")
    print(f"  {n_multi} packages have multiple versions present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
