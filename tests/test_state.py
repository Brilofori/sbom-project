import json

import pytest

import scan_all
from helpers import BASELINE_EVENTS, F127, F128, IMG, T0, by_kind, read_events, run


def test_baseline_sends_inventory_and_vulnerabilities(db, wazuh_log):
    kinds = by_kind(run(db, F127, wazuh_log, 0))
    assert len(kinds["component"]) == 8          # 7 packages + the OS; application groupings excluded
    assert len(kinds["vulnerability"]) == 7      # CVE-2024-5535 counts once per affected package
    assert {e["cause"] for e in kinds["component"] + kinds["vulnerability"]} == {"baseline"}


def test_identical_rescan_sends_nothing(db, wazuh_log):
    run(db, F127, wazuh_log, 0)
    assert run(db, F127, wazuh_log, 1) == []


def test_point_release_rebuild_is_not_a_flood(db, wazuh_log):
    run(db, F127, wazuh_log, 0)
    events = run(db, F128, wazuh_log, 1)
    kinds = by_kind(events)
    assert sorted(e["package_name"] for e in kinds["component_changed"]) == ["debian", "libc6", "libssl3", "openssl"]
    assert [e["package_name"] for e in kinds["component"]] == ["curl"]
    assert [e["package_name"] for e in kinds["component_removed"]] == ["zlib1g"]
    assert [(e["cve_id"], e["cause"]) for e in kinds["vulnerability"]] == [("CVE-2024-2398", "image_changed")]
    assert sorted((e["cve_id"], e["package_name"]) for e in kinds["vulnerability_resolved"]) == [
        ("CVE-2023-45853", "zlib1g"), ("CVE-2024-5535", "libssl3"), ("CVE-2024-5535", "openssl")]
    # bash, pip and jackson-databind produce nothing, although every Debian purl changed
    assert len(events) == 4 + 1 + 1 + 1 + 3
    libc = next(e for e in kinds["component_changed"] if e["package_name"] == "libc6")
    assert (libc["previous_version"], libc["installed_version"]) == ("2.36-9+deb12u7", "2.36-9+deb12u8")


def test_new_cve_on_unchanged_image_is_labelled_db_update(db, wazuh_log, tmp_path):
    run(db, F128, wazuh_log, 0)
    bom = json.loads(F128.read_text())
    bash = next(c for c in bom["components"] if c.get("name") == "bash")
    bom["vulnerabilities"].append({
        "id": "CVE-2026-0001", "source": {"name": "debian"},
        "ratings": [{"source": {"name": "debian"}, "severity": "high"}],
        "affects": [{"ref": bash["bom-ref"], "versions": [{"version": bash["version"], "status": "affected"}]}]})
    updated = tmp_path / "same_image_new_db.json"
    updated.write_text(json.dumps(bom))
    events = run(db, updated, wazuh_log, 1)
    assert [(e["sbom_event"], e["cve_id"], e["cause"]) for e in events] == [
        ("vulnerability", "CVE-2026-0001", "db_update")]


def test_regression_after_resolution(db, wazuh_log):
    run(db, F127, wazuh_log, 0)
    run(db, F128, wazuh_log, 1)
    kinds = by_kind(run(db, F127, wazuh_log, 2))  # rolled back to the old build
    assert sorted((e["cve_id"], e["package_name"]) for e in kinds["vulnerability"]) == [
        ("CVE-2023-45853", "zlib1g"), ("CVE-2024-5535", "libssl3"), ("CVE-2024-5535", "openssl")]
    assert {e["cause"] for e in kinds["vulnerability"]} == {"regression"}
    assert [(e["package_name"], e["cause"]) for e in kinds["component"]] == [("zlib1g", "re-added")]
    assert [e["cve_id"] for e in kinds["vulnerability_resolved"]] == ["CVE-2024-2398"]


def test_failed_delivery_does_not_advance_state(db, wazuh_log, tmp_path):
    with pytest.raises(OSError):
        scan_all.ingest(db, IMG, F127, host="node-01", wazuh_log=str(tmp_path / "no-dir" / "x.jsonl"),
                        eps=0, now=T0)
    for name in ("component_state", "vuln_state", "scans"):
        assert db[name].count_documents({}) == 0
    assert len(run(db, F127, wazuh_log, 1)) == BASELINE_EVENTS  # everything goes out next run


def test_hosts_keep_separate_state(db, wazuh_log):
    assert len(run(db, F127, wazuh_log, 0, host="node-01")) == BASELINE_EVENTS
    assert len(run(db, F127, wazuh_log, 1, host="node-02")) == BASELINE_EVENTS


def test_scan_document(db, wazuh_log):
    run(db, F127, wazuh_log, 0)
    run(db, F128, wazuh_log, 1)
    scan = db["scans"].find_one({"image_id": "sha256:" + "2" * 64})
    assert (scan["host"], scan["os"], scan["scanner_version"]) == ("node-01", "debian 12.8", "0.74.0")
    assert (scan["new_vulnerability_count"], scan["resolved_vulnerability_count"]) == (1, 3)
    assert (scan["changed_component_count"], scan["removed_component_count"]) == (4, 1)
    assert {r["cve_id"] for r in scan["resolved"]} == {"CVE-2024-5535", "CVE-2023-45853"}
    curl = next(v for v in scan["vulnerabilities"] if v["cve_id"] == "CVE-2024-2398")
    assert curl["is_new"] and curl["cause"] == "image_changed"
    assert curl["fixed_version"] == "7.88.1-10+deb12u10"
    assert "description" not in curl  # stored once per CVE instead
    assert db["cve_info"].find_one({"cve_id": "CVE-2024-2398"})["description"].startswith("Test description")


def test_events_carry_the_fields_the_wazuh_rules_use(db, wazuh_log):
    for e in run(db, F127, wazuh_log, 0):
        assert e["source"] == "trivy" and e["image"] == IMG and e["timestamp"] and e["package_name"]
    v = next(e for e in read_events(wazuh_log)
             if e.get("cve_id") == "CVE-2024-5535" and e["package_name"] == "libssl3")
    assert (v["severity"], v["max_severity"], v["fixed_version"]) == ("high", "critical", "3.0.15-1~deb12u1")


def test_deliver_throttles_large_batches(monkeypatch, wazuh_log):
    sleeps = []
    monkeypatch.setattr(scan_all.time, "sleep", sleeps.append)
    assert scan_all.deliver([{"n": i} for i in range(5)], wazuh_log, eps=2) == 5
    assert len(sleeps) == 2 and len(read_events(wazuh_log)) == 5


def test_legacy_state_is_moved_aside(db, wazuh_log):
    db["vuln_state"].create_index([("image", 1), ("cve_id", 1), ("purl", 1)], unique=True)
    db["vuln_state"].insert_one({"image": IMG, "cve_id": "CVE-1", "purl": "pkg:deb/debian/x@1", "first_seen": T0})
    db["component_state"].insert_one({"image": IMG, "comp_key": "pkg:deb/debian/x@1", "first_seen": T0})
    assert sorted(scan_all.migrate_legacy_state(db)) == ["component_state_legacy", "vuln_state_legacy"]
    scan_all.ensure_indexes(db)
    assert db["vuln_state_legacy"].count_documents({}) == 1   # kept, not deleted
    assert len(run(db, F127, wazuh_log, 0)) == BASELINE_EVENTS
    assert scan_all.migrate_legacy_state(db) == []


def test_empty_legacy_collection_with_old_index_is_moved_aside(db, wazuh_log):
    db["vuln_state"].create_index([("image", 1), ("cve_id", 1), ("purl", 1)], unique=True)
    assert scan_all.migrate_legacy_state(db) == ["vuln_state_legacy"]
    scan_all.ensure_indexes(db)
    kinds = by_kind(run(db, F127, wazuh_log, 0))  # CVE-2024-5535 hits two packages
    assert len([e for e in kinds["vulnerability"] if e["cve_id"] == "CVE-2024-5535"]) == 2


def test_rebaseline_resends_everything(db, wazuh_log):
    run(db, F127, wazuh_log, 0)
    assert len(scan_all.rebaseline(db)) == 2
    assert len(run(db, F127, wazuh_log, 1)) == BASELINE_EVENTS
