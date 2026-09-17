#!/usr/bin/env python3
from datetime import datetime, timezone

def load_wazuh(path):
    packages = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split("|", 1)
            if len(parts) == 2:
                packages[parts[0]] = parts[1]
    return packages

def load_trivy(path):
    packages = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split("|", 1)
            if len(parts) == 2:
                name, version = parts
                if name in packages:
                    packages[name].add(version)
                else:
                    packages[name] = {version}
    return packages

wazuh = load_wazuh("/home/kojo/wazuh_inventory.txt")
trivy_raw = load_trivy("/home/kojo/trivy_inventory.txt")
trivy = {n: sorted(v) for n, v in trivy_raw.items()}

shared = sorted(set(wazuh) & set(trivy))
wazuh_only = sorted(set(wazuh) - set(trivy))
trivy_only = sorted(set(trivy) - set(wazuh))

version_differs = []
for name in shared:
    if wazuh[name] not in trivy[name]:
        version_differs.append((name, wazuh[name], trivy[name]))

print(f"Wazuh host packages: {len(wazuh)}")
print(f"Trivy container components: {sum(len(v) for v in trivy.values())}")
print(f"Shared names: {len(shared)}")
print(f"Different versions: {len(version_differs)}")
print(f"Wazuh only: {len(wazuh_only)}")
print(f"Trivy only: {len(trivy_only)}")
print()
if version_differs:
    print("Same name, different version:")
    for name, w, t in version_differs:
        print(f"  {name}: host={w}  container={', '.join(t)}")
print()
if trivy_only:
    print("Only in container (invisible to Wazuh):")
    for name in trivy_only:
        print(f"  {name} ({', '.join(trivy[name])})")
