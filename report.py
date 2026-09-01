import sys
from datetime import datetime, timezone
from pymongo import MongoClient

def report(image_tag, output_path=None):
    db = MongoClient("mongodb://localhost:27017")["sweri_sbom"]

    scan = db["scans"].find_one(
        {"image": image_tag},
        sort=[("scanned_at", -1)]
    )
    if not scan:
        print(f"No scans found for {image_tag}")
        return

    vulns = scan.get("vulnerabilities", [])
    components = scan.get("components", [])

    # severity breakdown
    severity_counts = {}
    for v in vulns:
        sev = (v.get("severity") or "unknown").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # fixable: has a fixed_version
    fixable = [v for v in vulns if v.get("fixed_version")]

    # new findings from this scan
    new_findings = [v for v in vulns if v.get("is_new")]

    # critical and high only, sorted by severity then CVE
    actionable = [v for v in vulns
                  if (v.get("severity") or "").lower() in ("critical", "high")]
    actionable.sort(key=lambda v: (
        0 if (v.get("severity") or "").lower() == "critical" else 1,
        v.get("cve_id", "")
    ))

    # build the report
    lines = []
    lines.append(f"# Vulnerability Summary: {image_tag}")
    lines.append("")
    lines.append(f"**Scan date:** {scan['scanned_at'].strftime('%d %B %Y, %H:%M UTC')}")
    lines.append(f"**Components:** {scan.get('component_count', len(components))}")
    lines.append(f"**Total vulnerabilities:** {len(vulns)}")
    lines.append(f"**New since last scan:** {scan.get('new_vulnerability_count', len(new_findings))}")
    lines.append(f"**With fix available:** {len(fixable)}")
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

    if actionable:
        lines.append("## Critical and High Findings")
        lines.append("")
        lines.append("| CVE | Severity | Package | Installed | Fix Available |")
        lines.append("|-----|----------|---------|-----------|---------------|")
        for v in actionable[:50]:
            fix = v.get("fixed_version") or "no fix"
            lines.append(
                f"| {v.get('cve_id', 'N/A')} "
                f"| {(v.get('severity') or 'unknown').upper()} "
                f"| {v.get('package_name', 'N/A')} {v.get('installed_version', '')} "
                f"| {v.get('installed_version', 'N/A')} "
                f"| {fix} |"
            )
        if len(actionable) > 50:
            lines.append(f"| ... | ... | {len(actionable) - 50} more | ... | ... |")
        lines.append("")

    if fixable:
        lines.append("## Packages With Available Fixes (all severities)")
        lines.append("")
        lines.append("| CVE | Severity | Package | Installed | Fixed Version |")
        lines.append("|-----|----------|---------|-----------|---------------|")
        seen = set()
        for v in sorted(fixable, key=lambda x: x.get("cve_id", "")):
            key = (v.get("cve_id"), v.get("purl"))
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                f"| {v.get('cve_id', 'N/A')} "
                f"| {(v.get('severity') or 'unknown').upper()} "
                f"| {v.get('package_name', 'N/A')} "
                f"| {v.get('installed_version', 'N/A')} "
                f"| {v.get('fixed_version')} |"
            )
            if len(seen) >= 30:
                lines.append(f"| ... | ... | {len(fixable) - 30} more fixable | ... | ... |")
                break
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

    lines.append("## Notes")
    lines.append("")
    lines.append("- This report covers OS-level packages only. Python packages "
                 "installed via Conda are not detected by Trivy's current scanner "
                 "(see Conda detection gap finding).")
    lines.append("- linux-libc-dev entries carry kernel CVEs that are frequently "
                 "not exploitable in a userspace container context.")
    lines.append("")
    lines.append("---")
    lines.append(f"*Generated {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')}*")

    text = "\n".join(lines)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Report written to {output_path}")
    else:
        print(text)

if __name__ == "__main__":
    image = sys.argv[1] if len(sys.argv) > 1 else "pytorch/pytorch:latest"
    out = sys.argv[2] if len(sys.argv) > 2 else None
    report(image, out)