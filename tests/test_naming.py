"""A build server over many runs, at random: builds take the moving local tag, get versioned
and pushed (taking `latest`), gain extra names, and lose tags; some images have no packages
at all. An image never changes, so whatever happens to its tags it must be reported in one
run only: in full under a new name, or as what changed under a name another image had. And
no name is ever reported for two images in one run. Each seed is a different, repeatable
history."""
import json
import random
from collections import defaultdict

import pytest

import scan_all
from helpers import F127, F128, FakeDocker, findings


@pytest.fixture
def host(monkeypatch, tmp_path, db):
    docker = FakeDocker()
    monkeypatch.setattr(scan_all.subprocess, "run", docker)
    monkeypatch.setattr(scan_all, "OUT_DIR", tmp_path / "out")
    monkeypatch.setattr(scan_all, "WAZUH_JSONL", str(tmp_path / "log" / "trivy-findings.jsonl"))
    monkeypatch.setattr(scan_all, "WAZUH_EPS", 0)
    monkeypatch.setattr(scan_all, "get_db", lambda: db)
    return docker


@pytest.fixture
def no_packages(tmp_path):
    bom = json.loads(F127.read_text())
    bom["components"], bom["vulnerabilities"], bom["dependencies"] = [], [], []
    path = tmp_path / "scratch.cdx.json"
    path.write_text(json.dumps(bom))
    return path


def holder(docker, tag):
    return next((i for i, img in docker.images.items() if tag in img["tags"]), None)


def move(docker, tag, to):
    old = holder(docker, tag)
    if old:
        docker.images[old]["tags"].remove(tag)
    docker.images[to]["tags"].append(tag)


@pytest.mark.parametrize("seed", range(20))
def test_a_build_server_never_hears_about_an_image_twice(host, no_packages, seed, capsys):
    rnd = random.Random(seed)
    builds, reported, first_run = 0, 0, {}
    for step in range(60):
        op = rnd.choice(["build", "build", "version", "untag", "alias", "scan", "scan"])
        current = holder(host, "app:optimized")
        if op == "build":
            builds += 1
            host.image(f"sha256:build{builds}", fixture=rnd.choice([F127, F128, no_packages]))
            move(host, "app:optimized", f"sha256:build{builds}")
        elif op == "version" and current and not any("/app:v" in t for t in host.images[current]["tags"]):
            host.images[current]["tags"].append(f"acr.io/app:v{step}")
            move(host, "acr.io/app:latest", current)
        elif op == "untag":
            several = [i for i, img in host.images.items() if len(img["tags"]) >= 2]
            if several:
                tags = host.images[rnd.choice(several)]["tags"]
                tags.remove(rnd.choice(tags))
        elif op == "alias" and current:
            host.images[current]["tags"].append(f"local/alias:{step}")
        elif op == "scan" and current:
            assert scan_all.main([]) == 0
            run = findings(scan_all.WAZUH_JSONL)[reported:]
            reported += len(run)
            images_per_name = defaultdict(set)
            for e in run:
                images_per_name[e["image"]].add(e["image_id"])
                assert first_run.setdefault(e["image_id"], step) == step, (e["image_id"], e)
            assert all(len(ids) == 1 for ids in images_per_name.values()), images_per_name
    capsys.readouterr()
