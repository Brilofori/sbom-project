#!/usr/bin/env python3
"""Markdown vulnerability summary for one image's most recent scan.

Usage:
    python3 report.py IMAGE [OUTPUT.md] [--host HOST]

scan_all.py also writes one of these per image to out/report_<image>.md after each scan.
"""
import argparse
import sys
from datetime import datetime, timezone

from sbom_common import get_db, latest_scan

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE", "UNKNOWN"]
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def _sev(v):
    return (v.get("severity") or "unknown").upper()


def _cell(value):
    return str(value if value not in (None, "") else "-").replace("|", "\\|")


def _when(value):
    if isinstance(value, datetime):
        return value.strftime("%d %B %Y, %H:%M UTC")
    return str(value) if value else "unknown"


def build_report(scan):
    image = scan["image"]
    vulns = scan.get("vulnerabilities") or []
    components = scan.get("components") or []

    counts = {}
    for v in vulns:
        counts[_sev(v)] = counts.get(_sev(v), 0) + 1

    # one row per CVE + installed package, even if several copies are installed
    unique = {}
    for v in vulns:
        unique.setdefault((v.get("cve_id"), v.get("package_name"), v.get("installed_version")), v)
    rows = sorted(unique.values(),
                  key=lambda v: (_RANK.get(_sev(v), len(SEVERITIES)), v.get("cve_id") or ""))
    actionable = [v for v in rows if _sev(v) in ("CRITICAL", "HIGH")]
    fixable = [v for v in rows if v.get("fixed_version")]
    new = [v for v in rows if v.get("is_new")]
    resolved = scan.get("resolved") or []
    conda = sum(1 for c in components if (c.get("purl") or "").startswith("pkg:conda/"))

    image_id = scan.get("image_id") or "unknown"
    lines = [
        f"# Vulnerability Summary: {image}",
        "",
        f"**Scan date:** {_when(scan.get('scanned_at'))}",
        f"**Host:** {scan.get('host') or 'unknown'}",
        f"**Image ID:** {image_id[:19]}",
        f"**OS:** {scan.get('os') or 'unknown'}",
        f"**Scanner:** trivy {scan.get('scanner_version') or 'unknown'} "
        f"(vulnerability DB updated {scan.get('db_updated_at') or 'unknown'})",
        f"**Components:** {scan.get('component_count', len(components))}",
        f"**Total vulnerabilities:** {scan.get('vulnerability_count', len(vulns))}",
        f"**New since last scan:** {scan.get('new_vulnerability_count', len(new))}",
        f"**Resolved since last scan:** {scan.get('resolved_vulnerability_count', len(resolved))}",
        f"**With fix available:** {len(fixable)}",
        f"**Critical + High:** {len(actionable)}",
        "",
    ]
    if scan.get("truncated"):
        lines += ["> This scan had too many findings to store in full (MongoDB's 16MB document "
                  "limit), so the per-CVE tables below are empty. The full Trivy output is in "
                  f"`{scan.get('source_file')}`.", ""]

    lines += ["## Severity Breakdown", "", "| Severity | Count |", "|----------|-------|"]
    for sev in SEVERITIES:
        if counts.get(sev):
            lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    def table(title, items, limit):
        if not items:
            return
        lines.extend([f"## {title}", "",
                      "| CVE | Severity | Package | Installed | Fixed in |",
                      "|-----|----------|---------|-----------|----------|"])
        for v in items[:limit]:
            lines.append(f"| {_cell(v.get('cve_id'))} | {_sev(v)} | {_cell(v.get('package_name'))} "
                         f"| {_cell(v.get('installed_version'))} "
                         f"| {_cell(v.get('fixed_version') or 'no fix yet')} |")
        if len(items) > limit:
            lines.append(f"\n... and {len(items) - limit} more")
        lines.append("")

    table("Critical and High Findings", actionable, 50)
    table("Packages With Available Fixes (all severities)", fixable, 30)

    if new:
        lines += ["## New Findings This Scan", ""]
        for v in new[:20]:
            cause = f" ({v['cause'].replace('_', ' ')})" if v.get("cause") else ""
            lines.append(f"- **[{_sev(v)}]** {v.get('cve_id')} in {v.get('package_name')} "
                         f"{v.get('installed_version') or ''}{cause}")
        if len(new) > 20:
            lines.append(f"- ... and {len(new) - 20} more")
        lines.append("")

    if resolved:
        lines += ["## Resolved Since Last Scan", ""]
        for v in resolved[:20]:
            lines.append(f"- {v.get('cve_id')} in {v.get('package_name')} "
                         f"(was {v.get('installed_version') or '?'})")
        if len(resolved) > 20:
            lines.append(f"- ... and {len(resolved) - 20} more")
        lines.append("")

    lines += [
        "## Notes",
        "",
        "- Severity is Trivy's own: the rating from the package's distribution (e.g. Debian's "
        "for a Debian package), then GitHub Advisory for GHSA IDs, then NVD. The worst rating "
        "from any source is kept as `max_severity` in MongoDB and in the Wazuh events.",
        "- Coverage: OS packages, plus language packages Trivy can read from the image "
        "(pip-installed Python packages with .dist-info metadata, npm, jars, Go binaries). "
        "Conda is a known gap: Trivy only lists Conda packages from named environments "
        "(`<conda>/envs/<name>/`), not the base environment, and it never matches "
        "vulnerabilities for Conda packages.",
    ]
    if conda:
        lines.append(f"- This image has {conda} Conda packages in its inventory. They are "
                     "listed but not checked for vulnerabilities.")
    lines += [
        "- linux-libc-dev entries carry kernel CVEs that are frequently not exploitable in a "
        "userspace container context.",
        "",
        "---",
        f"*Generated {_when(datetime.now(timezone.utc))}*",
        "",
    ]
    return "\n".join(lines)


def write_report(db, image, out_path, host=None):
    """Write the report for an image's latest scan. Returns False if never scanned."""
    scan = latest_scan(db, image, host)
    if not scan:
        return False
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(build_report(scan))
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description="Markdown vulnerability summary for one image.")
    ap.add_argument("image", help="image reference as scanned, e.g. python:3.11-slim")
    ap.add_argument("output", nargs="?", help="write to this file instead of printing")
    ap.add_argument("--host", help="only use scans from this host")
    args = ap.parse_args(argv)

    scan = latest_scan(get_db(), args.image, args.host)
    if not scan:
        print(f"No scans found for {args.image}")
        return 1
    text = build_report(scan)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Report written to {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
