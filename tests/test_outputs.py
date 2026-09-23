import json

import pytest

import consolidated_report
import diff
import export_cyclonedx
import gap_analysis
import report
from helpers import F127, F128, IMG, T0, run
from sbom_common import latest_scan, latest_scans


def test_report_after_rebuild(db, wazuh_log):
    run(db, F127, wazuh_log, 0)
    run(db, F128, wazuh_log, 1)
    text = report.build_report(latest_scan(db, IMG))
    assert "| CVE-2020-9548 | CRITICAL | jackson-databind | 2.9.10.3 | 2.9.10.4 |" in text
    assert "**With fix available:** 3" in text
    assert "**Resolved since last scan:** 3" in text
    assert "CVE-2024-2398 in curl 7.88.1-10+deb12u8 (image changed)" in text
    assert "CVE-2024-5535 in libssl3 (was 3.0.14-1~deb12u2)" in text


def test_report_renders_scans_saved_by_the_old_version():
    old = {"image": "pytorch/pytorch:latest", "host": "sweri-node-01", "scanned_at": T0,
           "scanner_version": "0.74.0", "component_count": 1, "vulnerability_count": 1,
           "new_vulnerability_count": 1,
           "components": [{"name": "libc6", "version": "2.35", "type": "library",
                           "purl": "pkg:deb/ubuntu/libc6@2.35"}],
           "vulnerabilities": [{"cve_id": "CVE-1", "severity": "high", "fixed_version": None,
                                "description": "d", "package_name": "libc6", "installed_version": "2.35",
                                "purl": "pkg:deb/ubuntu/libc6@2.35", "is_new": True, "first_seen": T0}]}
    assert "| CVE-1 | HIGH | libc6 | 2.35 | no fix yet |" in report.build_report(old)


def test_latest_scans_is_per_host_and_image(db, wazuh_log):
    run(db, F127, wazuh_log, 0, host="a")
    run(db, F128, wazuh_log, 1, host="a")
    run(db, F127, wazuh_log, 2, host="b")
    latest = {(s["host"], s["image_id"][-1]) for s in latest_scans(db)}
    assert latest == {("a", "2"), ("b", "1")}


def test_consolidated_inventory(db, wazuh_log):
    run(db, F127, wazuh_log, 0, image="app:12.7")
    run(db, F128, wazuh_log, 1, image="app:12.8")
    text, _, n_images, n_multi = consolidated_report.build_report(latest_scans(db))
    assert (n_images, n_multi) == (2, 4)  # debian, libc6, libssl3, openssl at two versions
    assert "- `2.36-9+deb12u7` — app:12.7 on node-01" in text
    assert "site-packages" not in text    # application groupings are not packages


def test_diff_last_two_scans_of_one_image(db, wazuh_log):
    run(db, F127, wazuh_log, 0)
    run(db, F128, wazuh_log, 1)
    r = diff.diff_scans(latest_scan(db, IMG, skip=1), latest_scan(db, IMG))
    assert sorted(c["name"] for c in r["changed"]) == ["debian", "libc6", "libssl3", "openssl"]
    assert [c["name"] for c in r["added"]] == ["curl"]
    assert [c["name"] for c in r["removed"]] == ["zlib1g"]
    assert r["unchanged_count"] == 3


def _merged():
    return export_cyclonedx.merge_boms([("node-01", "app:12.7", json.loads(F127.read_text())),
                                        ("node-01", "app:12.8", json.loads(F128.read_text()))],
                                       version="test")


def test_export_is_one_consistent_bom():
    bom = _merged()
    refs = [bom["metadata"]["component"]["bom-ref"]]

    def walk(components):
        for c in components:
            if c.get("bom-ref"):
                refs.append(c["bom-ref"])
            walk(c.get("components") or [])

    walk(bom["components"])
    assert len(refs) == len(set(refs))                      # unique across images
    known = set(refs)
    for d in bom["dependencies"]:
        assert d["ref"] in known and set(d["dependsOn"]) <= known
    for v in bom["vulnerabilities"]:
        assert all(a["ref"] in known for a in v["affects"])
    ids = [v["id"] for v in bom["vulnerabilities"]]
    assert len(ids) == len(set(ids))                        # merged by CVE
    bash = next(v for v in bom["vulnerabilities"] if v["id"] == "CVE-2019-18276")
    assert len(bash["affects"]) == 2                        # affects both images
    assert [c["name"] for c in bom["components"]] == ["app:12.7", "app:12.8"]


def test_export_validates_against_the_cyclonedx_schema():
    validation = pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion
    errors = validation.JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(_merged()))
    assert errors is None, errors


def test_gap_analysis_compare(tmp_path):
    w = tmp_path / "wazuh_inventory.txt"
    w.write_text("apt|2.4.14\nbash|5.1-6ubuntu1.1\nsudo|1.9.9p2\n")
    r = gap_analysis.compare(gap_analysis.load_pipe_file(w),
                             {"apt": {"3.0.3"}, "bash": {"5.1-6ubuntu1.1"}, "base-files": {"13.8"}})
    assert r["shared"] == ["apt", "bash"]
    assert r["version_differs"] == [("apt", ["2.4.14"], ["3.0.3"])]
    assert (r["wazuh_only"], r["trivy_only"]) == (["sudo"], ["base-files"])


def test_gap_analysis_reads_trivy_side_from_a_scan(db, wazuh_log):
    run(db, F127, wazuh_log, 0)
    pkgs = gap_analysis.load_from_scan(latest_scan(db, IMG))
    assert pkgs["libc6"] == {"2.36-9+deb12u7"} and "debian" not in pkgs
