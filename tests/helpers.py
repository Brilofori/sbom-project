import builtins
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import scan_all
from conftest import FIXTURES

T0 = datetime(2026, 9, 20, 2, 30, tzinfo=timezone.utc)
F127 = FIXTURES / "app_debian12.7.cdx.json"   # example/app:1.0 built on Debian 12.7
F128 = FIXTURES / "app_debian12.8.cdx.json"   # the same image rebuilt on Debian 12.8
IMG = "example/app:1.0"
BASELINE_EVENTS = 15                           # 8 packages (incl. the OS) + 7 CVE/package pairs
ONLY_IN_F127 = {"CVE-2023-45853", "CVE-2024-5535"}
ONLY_IN_F128 = {"CVE-2024-2398"}


def bom_image_id(fixture):
    """The image ID Trivy recorded in a CycloneDX fixture."""
    props = json.loads(Path(fixture).read_text())["metadata"]["component"]["properties"]
    return next(p["value"] for p in props if p["name"] == "aquasecurity:trivy:ImageID")


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class FakeDocker:
    """Stands in for the docker command, so both scanners run end to end without Docker.

    It keeps images with their tags (repo:tag) and registry digests (repo@sha256:...), and a
    pretend registry to download digests from, and follows the rules of Docker's classic
    image store. Trivy runs ("docker run ... trivy") write the CycloneDX fixture of the image
    they are pointed at, with that image's ID in it, as Trivy would. Install it with
    monkeypatch.setattr(scan_all.subprocess, "run", docker): both scanners use it then."""

    def __init__(self):
        self.images = {}       # image ID -> {"tags", "digests", "fixture", "error"}
        self.registry = {}     # repo@sha256:... -> the image ID downloading it gives
        self.pulls, self.scans, self.removed = [], [], []
        self.wrote = lambda path: None   # told about every file Trivy writes (see RootOwned)

    def image(self, image_id, tags=(), digests=(), fixture=F127, error=None):
        """An image on this machine. `error` makes Trivy fail on it with that message. An
        image stays here when its tags move to other images, as in Docker, until removed."""
        self.images[image_id] = {"tags": list(tags), "digests": list(digests),
                                 "fixture": fixture, "error": error, "here": True}

    def in_registry(self, ref, image_id, fixture=F127, error=None):
        """An image only the registry has, until it is downloaded as `ref` (repo@sha256:...)."""
        self.images.setdefault(image_id, {"tags": [], "digests": [], "fixture": fixture,
                                          "error": error, "here": False})
        self.registry[ref] = image_id

    def here(self, image_id):
        return bool(self.images.get(image_id, {}).get("here"))

    def resolve(self, ref):
        """The ID of the image `ref` (a tag, repo@digest or image ID) names on this machine,
        as Docker would find it, or None."""
        if ref.startswith("sha256:"):
            return ref if self.here(ref) else None
        if "@" not in ref and ":" not in ref.rsplit("/", 1)[-1]:
            ref += ":latest"
        return next((image_id for image_id, img in self.images.items()
                     if img["here"] and (ref in img["tags"] or ref in img["digests"])), None)

    def listing(self):
        """`docker images --no-trunc --digests` rows: one per tag and digest of the same repo,
        and a <none> tag for a digest whose repo has no tag here."""
        rows = []
        for image_id, img in self.images.items():
            if not img["here"]:
                continue
            tagged = set()
            for tag in img["tags"]:
                repo = tag.rsplit(":", 1)[0]
                tagged.add(repo)
                digests = [d for d in img["digests"] if d.split("@")[0] == repo] or [f"{repo}@<none>"]
                rows += [f"{image_id}\t{tag}\t{d}" for d in digests]
            rows += [f"{image_id}\t{d.split('@')[0]}:<none>\t{d}" for d in img["digests"]
                     if d.split("@")[0] not in tagged]
        return "".join(row + "\n" for row in rows + ["<none>\t<none>:<none>\t<none>@<none>"])

    def __call__(self, cmd, **kwargs):
        if cmd[:2] == ["docker", "images"]:
            return Result(stdout=self.listing())
        if cmd[:3] == ["docker", "image", "inspect"]:
            found = self.resolve(cmd[-1])
            return Result(stdout=f"{found}\n") if found else \
                Result(1, stderr=f"Error: No such image: {cmd[-1]}")
        if cmd[:2] == ["docker", "pull"]:
            ref = cmd[-1]
            self.pulls.append(ref)
            image_id = self.resolve(ref) or self.registry.get(ref)
            if "@" not in ref or not image_id:     # the scanners only ever pull by digest
                return Result(1, stderr=f"Error response from daemon: manifest for {ref} not found")
            img = self.images[image_id]
            img["here"] = True
            if ref not in img["digests"]:
                img["digests"].append(ref)
            return Result()
        if cmd[:2] == ["docker", "rmi"]:
            ref = cmd[-1]
            image_id = self.resolve(ref)
            if not image_id:
                return Result(1, stderr=f"Error: No such image: {ref}")
            img = self.images[image_id]
            if ref in img["digests"]:
                img["digests"].remove(ref)
            else:
                img["tags"].remove(ref)
                repo = ref.rsplit(":", 1)[0]
                if not any(t.rsplit(":", 1)[0] == repo for t in img["tags"]):
                    # the classic store forgets a repository's digests with its last tag
                    img["digests"] = [d for d in img["digests"] if d.split("@")[0] != repo]
            img["here"] = bool(img["tags"] or img["digests"])   # deleted with its last name
            self.removed.append(ref)
            return Result()
        if cmd[:2] == ["docker", "info"]:
            return Result(stdout="\n")
        if cmd[:2] == ["docker", "run"]:
            return self.trivy(cmd)
        raise AssertionError(f"unexpected command {cmd}")

    def trivy(self, cmd):
        if "--download-db-only" in cmd:
            return Result()
        if cmd[-3:] == ["version", "--format", "json"]:
            return Result(stdout=json.dumps({"Version": "0.74.0",
                                             "VulnerabilityDB": {"UpdatedAt": "2026-10-01T00:00:00Z"}}))
        target = cmd[-1]
        image_id = self.resolve(target)
        if "--image-src" not in cmd or cmd[cmd.index("--image-src") + 1] != "docker":
            return Result(1, stderr="FATAL test: Trivy must only read images from this machine")
        if not image_id:
            return Result(1, stderr=f'INFO ...\nFATAL unable to find the specified image "{target}"')
        img = self.images[image_id]
        if img["error"]:
            return Result(1, stderr=f"INFO ...\n{img['error']}")
        self.scans.append(target)
        out_dir = next(m for m in cmd if m.endswith(":/out")).rsplit(":", 1)[0]
        partial = cmd[cmd.index("--output") + 1].split("/out/", 1)[1]
        bom = json.loads(Path(img["fixture"]).read_text())
        bom["metadata"]["component"]["name"] = target          # as Trivy does
        for prop in bom["metadata"]["component"]["properties"]:
            if prop["name"] == "aquasecurity:trivy:ImageID":
                prop["value"] = image_id
        (Path(out_dir) / partial).write_text(json.dumps(bom))
        self.wrote(Path(out_dir) / partial)
        return Result()


class RootOwned:
    """Trivy runs as root in its container, so the files it writes belong to root. The
    scanner's own user (`sbom` in the README) owns the folder: it can read, rename and
    replace those files, but not write into them. This makes scan_all behave that way,
    since the tests run as root."""

    def __init__(self, monkeypatch, docker):
        import scan_all
        self.paths = set()
        docker.wrote = lambda path: self.paths.add(os.path.realpath(path))
        real_open, real_replace = builtins.open, os.replace

        def open_(file, mode="r", *args, **kwargs):
            if set(mode) & set("wa+") and os.path.realpath(file) in self.paths:
                raise PermissionError(13, "Permission denied", os.fspath(file))
            return real_open(file, mode, *args, **kwargs)

        def replace(src, dst):
            real_replace(src, dst)
            src, dst = os.path.realpath(src), os.path.realpath(dst)
            if src in self.paths:
                self.paths.add(dst)
            else:
                self.paths.discard(dst)
            self.paths.discard(src)

        monkeypatch.setattr(scan_all, "open", open_, raising=False)
        monkeypatch.setattr(scan_all.shutil, "open", open_, raising=False)
        monkeypatch.setattr(scan_all, "os", SimpleNamespace(**{**vars(os), "replace": replace}))


class FakeRegistry:
    """Stands in for V2Registry: a registry's repositories, their tags, each tag's digest,
    and each digest's config digest (the image ID Docker's classic store gives the image).
    Install with monkeypatch.setattr(scan_registry, "V2Registry", registry)."""

    def __init__(self, host, repos):
        self.host = host
        self.repos = repos      # {repo: {tag: (digest, config digest)}}

    def __call__(self, host, insecure=False):
        assert host == self.host
        return self

    def catalog(self):
        return sorted(self.repos)

    def tags(self, repo):
        return list(self.repos[repo])

    def digest(self, repo, tag, platform):
        return self.repos[repo][tag][0]

    def size(self, repo, ref, platform):
        return None

    def config_digest(self, repo, ref, platform):
        return next((config for digest, config in self.repos[repo].values() if digest == ref), None)


def read_events(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def findings(path):
    """The events in the Wazuh log, without the run summaries."""
    return [e for e in read_events(path) if e["sbom_event"] != "scan_run"]


def run(db, fixture, log, hour, host="node-01", image=IMG):
    """Ingest one scan and return only the events that run wrote."""
    before = len(read_events(log))
    scan_all.ingest(db, image, fixture, host=host, wazuh_log=log, eps=0,
                    now=T0 + timedelta(hours=hour))
    return read_events(log)[before:]


def by_kind(events):
    out = {}
    for e in events:
        out.setdefault(e["sbom_event"], []).append(e)
    return out
