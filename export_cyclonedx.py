#!/usr/bin/env python3
"""Deliverable 3: one consolidated CycloneDX SBOM covering every scanned image.

Takes the latest Trivy CycloneDX file for each (host, image) and merges them into one
BOM. Each image becomes a `container` component with its packages nested under it,
every bom-ref is prefixed with "<host>/<image>#" so refs stay unique across images, and
vulnerabilities are merged by ID (one entry per CVE listing every affected package).

Usage:
    python3 export_cyclonedx.py [--output FILE] [--host HOST] [--name NAME] [--version V]
    default output: out/sweri-consolidated.cdx.json
"""
import argparse
import copy
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sbom_common import BASE_DIR, OUT_DIR, get_db, latest_scans

ROOT_REF = "sweri-container-estate"


def _spec_key(version):
    try:
        return tuple(int(x) for x in version.split("."))
    except (AttributeError, ValueError):
        return (0,)


def merge_boms(entries, name="SWERI container estate", version=None, timestamp=None):
    """entries: [(host, image, cyclonedx_dict)] -> one CycloneDX dict."""
    now = datetime.now(timezone.utc)
    spec = max([e[2].get("specVersion") or "1.5" for e in entries] + ["1.5"], key=_spec_key)
    components, vulns, tools = [], {}, {}
    dependencies = {ROOT_REF: []}

    for host, image, bom in entries:
        prefix = f"{host}/{image}#"

        def ref(r, prefix=prefix):
            return prefix + r

        meta = bom.get("metadata") or {}
        img = copy.deepcopy(meta.get("component") or {})
        img["bom-ref"] = ref(img.get("bom-ref") or "image")
        img["type"] = img.get("type") or "container"
        img["name"] = image
        img["properties"] = (img.get("properties") or []) + [{"name": "sweri:host", "value": host}]
        children = []
        for original in bom.get("components") or []:
            comp = copy.deepcopy(original)
            if comp.get("bom-ref"):
                comp["bom-ref"] = ref(comp["bom-ref"])
            children.append(comp)
        if children:
            img["components"] = children
        components.append(img)
        dependencies[ROOT_REF].append(img["bom-ref"])

        for d in bom.get("dependencies") or []:
            refs = dependencies.setdefault(ref(d["ref"]), [])
            refs.extend(ref(x) for x in d.get("dependsOn") or [] if ref(x) not in refs)

        for original in bom.get("vulnerabilities") or []:
            v = copy.deepcopy(original)
            if v.get("bom-ref"):
                v["bom-ref"] = ref(v["bom-ref"])
            for a in v.get("affects") or []:
                if a.get("ref"):
                    a["ref"] = ref(a["ref"])
            merged = vulns.get(v.get("id"))
            if merged is None:
                vulns[v.get("id")] = v
                continue
            merged.setdefault("affects", []).extend(v.get("affects") or [])
            recs = [r for r in (merged.get("recommendation") or "").split("; ") if r]
            recs += [r for r in (v.get("recommendation") or "").split("; ") if r and r not in recs]
            if recs:
                merged["recommendation"] = "; ".join(sorted(recs))

        tool_src = meta.get("tools") or {}
        for t in (tool_src.get("components", []) if isinstance(tool_src, dict) else tool_src):
            tools[(t.get("name"), t.get("version"))] = t

    return {
        "$schema": f"http://cyclonedx.org/schema/bom-{spec}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": list(tools.values())},
            "component": {"type": "application", "bom-ref": ROOT_REF, "name": name,
                          "version": version or now.strftime("%Y.%m.%d")},
        },
        "components": components,
        "dependencies": [{"ref": r, "dependsOn": d} for r, d in dependencies.items()],
        "vulnerabilities": [vulns[k] for k in sorted(vulns, key=str)],
    }


def load_entries(scans):
    entries, skipped = [], []
    for scan in scans:
        path = Path(scan.get("source_file") or "")
        if not path.is_absolute():
            path = BASE_DIR / path
        try:
            with open(path, encoding="utf-8") as f:
                bom = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            skipped.append(f"{scan['image']}: {e}")
            continue
        if bom.get("bomFormat") != "CycloneDX":
            skipped.append(f"{scan['image']}: {path} is not a CycloneDX file")
            continue
        entries.append((scan.get("host") or "unknown", scan["image"], bom))
    return entries, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(description="Merge the latest per-image SBOMs into one CycloneDX file.")
    ap.add_argument("--output", default=str(OUT_DIR / "sweri-consolidated.cdx.json"))
    ap.add_argument("--host", help="only images scanned on this host")
    ap.add_argument("--name", default="SWERI container estate")
    ap.add_argument("--version", help="version label for the BOM (default: today's date)")
    args = ap.parse_args(argv)

    entries, skipped = load_entries(latest_scans(get_db(), host=args.host))
    for s in skipped:
        print(f"  skipped {s}")
    if not entries:
        print("Nothing to export: no scans with a readable Trivy output file")
        return 1
    bom = merge_boms(entries, name=args.name, version=args.version)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2)
    n_pkgs = sum(len(c.get("components") or []) for c in bom["components"])
    print(f"Consolidated SBOM written to {args.output}")
    print(f"  {len(entries)} images, {n_pkgs} components, {len(bom['vulnerabilities'])} vulnerabilities "
          f"(CycloneDX {bom['specVersion']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
