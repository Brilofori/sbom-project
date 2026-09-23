#!/usr/bin/env python3
"""Compare package inventories.

Usage:
    python3 diff.py IMAGE              what changed between the last two scans of IMAGE
    python3 diff.py IMAGE_A IMAGE_B    latest scan of IMAGE_A vs latest scan of IMAGE_B
    --host HOST                        only use scans from this host

Packages are matched on identity (the purl without version and qualifiers, e.g.
pkg:deb/debian/libc6), so a version bump shows as "changed", not as removed + added,
and a package only matches the same package from the same ecosystem.
"""
import argparse
import sys

from sbom_common import PACKAGE_TYPES, get_db, identity, latest_scan


def packages(scan):
    out = {}
    for c in scan.get("components") or []:
        if c.get("type") not in PACKAGE_TYPES or not c.get("name"):
            continue
        entry = out.setdefault(identity(c.get("purl"), c.get("type"), c.get("name")),
                               {"name": c["name"], "type": c.get("type"), "versions": set()})
        entry["versions"].add(c.get("version") or "")
    return out


def diff_scans(scan_a, scan_b):
    a, b = packages(scan_a), packages(scan_b)
    changed, unchanged = [], 0
    for key in sorted(a.keys() & b.keys()):
        if a[key]["versions"] == b[key]["versions"]:
            unchanged += 1
        else:
            changed.append({"name": a[key]["name"], "type": a[key]["type"],
                            "old_versions": sorted(a[key]["versions"]),
                            "new_versions": sorted(b[key]["versions"])})
    return {"added": [b[k] for k in sorted(b.keys() - a.keys())],
            "removed": [a[k] for k in sorted(a.keys() - b.keys())],
            "changed": changed,
            "unchanged_count": unchanged}


def print_diff(label_a, label_b, result):
    print(f"\n=== Diff: {label_a}  ->  {label_b} ===\n")
    for title, sign, key in (("Added", "+", "added"), ("Removed", "-", "removed")):
        print(f"{title} ({len(result[key])}):")
        for c in sorted(result[key], key=lambda c: c["name"]):
            print(f"  {sign} {c['name']} {', '.join(sorted(c['versions']))}  [{c['type']}]")
        print()
    print(f"Version changed ({len(result['changed'])}):")
    for e in sorted(result["changed"], key=lambda e: e["name"]):
        print(f"  ~ {e['name']}: {', '.join(e['old_versions'])} -> {', '.join(e['new_versions'])}")
    print(f"\nUnchanged: {result['unchanged_count']}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Compare package inventories between scans.")
    ap.add_argument("image_a")
    ap.add_argument("image_b", nargs="?", help="omit to compare IMAGE_A's last two scans")
    ap.add_argument("--host", help="only use scans from this host")
    args = ap.parse_args(argv)
    db = get_db()

    if args.image_b:
        a = latest_scan(db, args.image_a, args.host)
        b = latest_scan(db, args.image_b, args.host)
        labels = (args.image_a, args.image_b)
        missing = [img for img, scan in ((args.image_a, a), (args.image_b, b)) if not scan]
        if missing:
            print(f"No scan found for {', '.join(missing)}")
            return 1
    else:
        b = latest_scan(db, args.image_a, args.host)
        a = latest_scan(db, args.image_a, args.host, skip=1)
        if not a:
            print(f"Need at least two scans of {args.image_a} to compare")
            return 1
        labels = tuple(f"{args.image_a} ({s['scanned_at']:%Y-%m-%d %H:%M})" for s in (a, b))

    result = diff_scans(a, b)
    print_diff(*labels, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
