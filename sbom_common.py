"""Settings and helpers shared by the SBOM pipeline scripts.

Every setting can be overridden with an environment variable (see README, "Configuration").
"""
import os
import sys
from pathlib import Path

from pymongo import MongoClient
from pymongo.errors import PyMongoError

BASE_DIR = Path(__file__).resolve().parent
MONGO_URI = os.environ.get("SBOM_MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("SBOM_DB", "sweri_sbom")
OUT_DIR = Path(os.environ.get("SBOM_OUT_DIR", str(BASE_DIR / "out")))

# CycloneDX component types that are real installed packages. Trivy also emits
# `application` components (a lockfile or site-packages directory grouping packages)
# and a `container` component for the image itself; those are not packages.
PACKAGE_TYPES = {"library", "framework", "operating-system"}


def get_db(timeout_ms=5000):
    """Connect and ping, so a stopped MongoDB fails in seconds with a readable message."""
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=timeout_ms)
    try:
        client.admin.command("ping")
    except PyMongoError as e:
        sys.exit(f"Cannot reach MongoDB at {MONGO_URI}: {e}\n"
                 "Is the container running?  docker ps -a | grep mongo   then   docker start mongodb")
    return client[DB_NAME]


def safe_name(image):
    """Image reference -> file-name-safe string."""
    return image.replace("/", "_").replace(":", "_").replace("@", "_")


def identity(purl, ctype=None, name=None):
    """Version-independent identity for a package.

    Trivy's purls embed the version and, for OS packages, the OS point release:
        pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64&distro=debian-12.7
    so every rebuild of a base image changes them. The identity drops both:
        pkg:deb/debian/libc6
    Components without a purl (e.g. the OS itself) fall back to "<type>:<name>".
    """
    if purl:
        return purl.split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[0]
    return f"{ctype}:{name}"


def latest_scans(db, host=None, image=None):
    """The most recent scan document for every (host, image) pair."""
    match = {}
    if host:
        match["host"] = host
    if image:
        match["image"] = image
    pipeline = [
        {"$match": match},
        {"$sort": {"host": 1, "image": 1, "scanned_at": -1}},
        {"$group": {"_id": {"host": "$host", "image": "$image"}, "scan_id": {"$first": "$_id"}}},
    ]
    ids = [d["scan_id"] for d in db["scans"].aggregate(pipeline, allowDiskUse=True)]
    return list(db["scans"].find({"_id": {"$in": ids}}).sort([("image", 1), ("host", 1)]))


def latest_scan(db, image, host=None, skip=0):
    """The most recent scan of one image (skip=1 gives the one before it)."""
    query = {"image": image}
    if host:
        query["host"] = host
    docs = list(db["scans"].find(query).sort("scanned_at", -1).skip(skip).limit(1))
    return docs[0] if docs else None
