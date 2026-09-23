import json

import scan_all
from helpers import F127
from sbom_common import identity


def bom():
    return json.loads(F127.read_text())


def vuln(cve):
    return next(v for v in bom()["vulnerabilities"] if v["id"] == cve)


def test_fixed_version_is_read_from_recommendation():
    _, flat, _ = scan_all.parse_sbom(bom())
    fixes = {(f["cve_id"], f["package_name"]): f["fixed_version"] for f in flat}
    assert fixes[("CVE-2024-5535", "libssl3")] == "3.0.15-1~deb12u1"   # two packages, "; "-joined
    assert fixes[("CVE-2024-5535", "openssl")] == "3.0.15-1~deb12u1"
    assert fixes[("CVE-2023-5752", "pip")] == "23.3"
    assert fixes[("CVE-2020-9548", "jackson-databind")] == "2.9.10.4"  # Maven group:name
    assert fixes[("CVE-2019-18276", "bash")] is None                   # no fix published


def test_fix_is_not_attributed_to_the_wrong_package():
    fixes = scan_all.fixed_versions({"recommendation": "Upgrade a to version 2"})
    assert scan_all.fixed_version_for(fixes, {"name": "a"}, 2) == "2"
    assert scan_all.fixed_version_for(fixes, {"name": "b"}, 2) is None


def test_severity_is_trivys_not_the_worst_vendors():
    assert scan_all.severities(vuln("CVE-2019-18276")) == ("low", "high")       # Debian, not CBL-Mariner
    assert scan_all.severities(vuln("CVE-2024-5535")) == ("high", "critical")
    assert scan_all.severities(vuln("CVE-2023-45853")) == ("critical", "critical")  # no Debian rating: NVD
    assert scan_all.severities(vuln("CVE-2023-5752")) == ("low", "medium")      # GHSA data source
    assert scan_all.severities(vuln("CVE-2025-0395")) == ("medium", "high")


def test_nvd_cvss_v2_rating_is_ignored_for_trivy_severity():
    v = {"id": "CVE-1", "source": {"name": "nvd"}, "ratings": [
        {"source": {"name": "nvd"}, "method": "CVSSv31", "severity": "medium"},
        {"source": {"name": "nvd"}, "method": "CVSSv2", "severity": "high"}]}
    assert scan_all.severities(v) == ("medium", "high")
    v["ratings"].reverse()
    assert scan_all.severities(v) == ("medium", "high")


def test_identity_ignores_version_and_os_point_release():
    a = identity("pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64&distro=debian-12.7")
    b = identity("pkg:deb/debian/libc6@2.36-9+deb12u8?arch=amd64&distro=debian-12.8")
    assert a == b == "pkg:deb/debian/libc6"
    assert identity("pkg:npm/%40babel/core@7.24.0") == "pkg:npm/%40babel/core"
    assert identity(None, "operating-system", "debian") == "operating-system:debian"


def test_image_metadata():
    m = scan_all.image_metadata(bom())
    assert m["image_id"] == "sha256:" + "1" * 64
    assert m["repo_digests"] == ["example/app@sha256:" + "1" * 64]
    assert m["os"] == "debian 12.7"
    assert m["trivy_version"] == "0.74.0"


def test_error_tail_shows_the_real_error():
    stderr = "\n".join(["INFO [vulndb] Downloading vulnerability DB..."] * 40
                       + ["FATAL Fatal error run error: unable to find the specified image"])
    assert scan_all.error_tail(stderr).startswith("FATAL")
