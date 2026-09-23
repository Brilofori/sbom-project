#!/usr/bin/env python3
"""Deliverable 4: host packages (Wazuh Syscollector) vs container image packages (Trivy).

1. On the Wazuh manager, export the host's package list (agent 001 = sweri-node-01):
       sudo sqlite3 /var/ossec/queue/db/001.db "SELECT name, version FROM sys_programs;" > wazuh_inventory.txt
   and copy it here:  scp <user>@<manager-ip>:~/wazuh_inventory.txt .
2. Compare it with an image's latest scan in MongoDB:
       python3 gap_analysis.py wazuh_inventory.txt --image python:3.9-slim
   or with a name|version file:
       python3 gap_analysis.py wazuh_inventory.txt --trivy trivy_inventory.txt
"""
import argparse
import sys

from sbom_common import PACKAGE_TYPES, get_db, latest_scan


def load_pipe_file(path):
    """name|version lines (sqlite3's default output) -> {name: {versions}}"""
    packages = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 2 and parts[0]:
                packages.setdefault(parts[0], set()).add(parts[1])
    return packages


def load_from_scan(scan):
    packages = {}
    for c in scan.get("components") or []:
        if c.get("type") in PACKAGE_TYPES and c.get("type") != "operating-system" and c.get("name"):
            packages.setdefault(c["name"], set()).add(c.get("version") or "")
    return packages


def compare(wazuh, trivy):
    shared = sorted(set(wazuh) & set(trivy))
    return {
        "shared": shared,
        "wazuh_only": sorted(set(wazuh) - set(trivy)),
        "trivy_only": sorted(set(trivy) - set(wazuh)),
        "version_differs": [(n, sorted(wazuh[n]), sorted(trivy[n]))
                            for n in shared if not wazuh[n] & trivy[n]],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Wazuh host inventory vs Trivy image inventory.")
    ap.add_argument("wazuh_inventory", help="name|version file exported from Syscollector")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--image", help="use this image's latest scan from MongoDB")
    src.add_argument("--trivy", help="name|version file for the image instead of MongoDB")
    ap.add_argument("--host", help="with --image: only use scans from this host")
    args = ap.parse_args(argv)

    wazuh = load_pipe_file(args.wazuh_inventory)
    if args.image:
        scan = latest_scan(get_db(), args.image, args.host)
        if not scan:
            print(f"No scan found for {args.image}")
            return 1
        trivy, label = load_from_scan(scan), f"{args.image} (scanned {scan['scanned_at']:%Y-%m-%d})"
    else:
        trivy, label = load_pipe_file(args.trivy), args.trivy

    r = compare(wazuh, trivy)
    print(f"Container: {label}")
    print(f"Wazuh host packages: {len(wazuh)}")
    print(f"Trivy container components: {sum(len(v) for v in trivy.values())}")
    print(f"Shared names: {len(r['shared'])}")
    print(f"Different versions: {len(r['version_differs'])}")
    print(f"Wazuh only: {len(r['wazuh_only'])}")
    print(f"Trivy only: {len(r['trivy_only'])}")
    if r["version_differs"]:
        print("\nSame name, different version:")
        for name, w, t in r["version_differs"]:
            print(f"  {name}: host={', '.join(w)}  container={', '.join(t)}")
    if r["trivy_only"]:
        print("\nOnly in container (invisible to Wazuh):")
        for name in r["trivy_only"]:
            print(f"  {name} ({', '.join(sorted(trivy[name]))})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
