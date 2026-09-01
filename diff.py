from pymongo import MongoClient

def get_components(image_tag):
    client = MongoClient("mongodb://localhost:27017")
    db = client["sweri_sbom"]
    doc = db["scans"].find_one({"image": image_tag}, sort=[("scanned_at", -1)])
    if not doc:
        raise ValueError(f"No scan found for {image_tag}")

    keyed = {}
    for c in doc["components"]:
        key = c["purl"] if c["purl"] else f"{c['type']}:{c['name']}"
        keyed[key] = c
    return keyed

def diff(image_a, image_b):
    a = get_components(image_a)
    b = get_components(image_b)

    # group by name first, this is the primary match key
    a_by_name = {}
    for k, c in a.items():
        a_by_name.setdefault(c["name"], []).append(c)
    b_by_name = {}
    for k, c in b.items():
        b_by_name.setdefault(c["name"], []).append(c)

    # names in both scans: these are either unchanged or version-changed
    # names in only one scan: these are genuinely added or removed
    names_in_both = set(a_by_name) & set(b_by_name)
    names_only_in_a = set(a_by_name) - set(b_by_name)
    names_only_in_b = set(b_by_name) - set(a_by_name)

    # genuinely removed: the package name doesn't exist at all in scan b
    removed = []
    for name in sorted(names_only_in_a):
        for c in a_by_name[name]:
            removed.append(c)

    # genuinely added: the package name doesn't exist at all in scan a
    added = []
    for name in sorted(names_only_in_b):
        for c in b_by_name[name]:
            added.append(c)

    # version changed: name exists in both, but versions differ
    changed = []
    for name in sorted(names_in_both):
        a_versions = {c["version"] for c in a_by_name[name]}
        b_versions = {c["version"] for c in b_by_name[name]}
        if a_versions != b_versions:
            changed.append({
                "name": name,
                "old_versions": sorted(a_versions),
                "new_versions": sorted(b_versions),
            })

    print(f"\n=== Diff: {image_a}  ->  {image_b} ===\n")

    print(f"Added ({len(added)}):")
    for c in sorted(added, key=lambda c: c["name"]):
        print(f"  + {c['name']} {c['version']}  [{c['type']}]")

    print(f"\nRemoved ({len(removed)}):")
    for c in sorted(removed, key=lambda c: c["name"]):
        print(f"  - {c['name']} {c['version']}  [{c['type']}]")

    print(f"\nVersion changed ({len(changed)}):")
    for entry in changed:
        print(f"  ~ {entry['name']}: {entry['old_versions']} -> {entry['new_versions']}")

    print(f"\nUnchanged: {len(names_in_both) - len(changed)}")

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged_count": len(names_in_both) - len(changed),
    }

if __name__ == "__main__":
    diff("python:3.9-slim", "python:3.11-slim")