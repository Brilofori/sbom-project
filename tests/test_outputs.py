import json

import pytest

import export_cyclonedx
import scan_all
from helpers import F127, F128, T0, run
from sbom_common import latest_scans


def test_latest_scans_is_per_host_and_image(db, wazuh_log):
    run(db, F127, wazuh_log, 0, host="a")
    run(db, F128, wazuh_log, 1, host="a")
    run(db, F127, wazuh_log, 2, host="b")
    latest = {(s["host"], s["image_id"][-1]) for s in latest_scans(db)}
    assert latest == {("a", "2"), ("b", "1")}


def test_an_image_reported_under_a_new_name_is_exported_once(db, wazuh_log):
    run(db, F127, wazuh_log, 0, host="a", image="acr/app:1.0")
    run(db, F127, wazuh_log, 1, host="a", image="app:optimized")      # the same image, renamed
    run(db, F127, wazuh_log, 2, host="b", image="acr/app:1.0")        # another machine
    assert {(s["host"], s["image"]) for s in latest_scans(db)} == {("a", "app:optimized"), ("b", "acr/app:1.0")}


def test_a_name_reported_since_as_another_tag_drops_out_of_the_export(db, wazuh_log):
    run(db, F128, wazuh_log, 0, host="a", image="app:optimized")      # an image of its own, then
    run(db, F127, wazuh_log, 1, host="b", image="app:optimized")      # another machine: unaffected
    scan_all.ingest(db, "acr/app:1.0", F127, host="a", wazuh_log=wazuh_log, eps=0,
                    now=T0.replace(hour=5), extra={"other_tags": "app:optimized, acr/app:latest"})
    assert {(s["host"], s["image"]) for s in latest_scans(db)} == {("a", "acr/app:1.0"), ("b", "app:optimized")}
    run(db, F128, wazuh_log, 9, host="a", image="app:optimized")      # later its own image again
    assert {(s["host"], s["image"]) for s in latest_scans(db)} == \
        {("a", "acr/app:1.0"), ("a", "app:optimized"), ("b", "app:optimized")}


def test_a_registry_image_stays_in_the_export_after_its_tag_moves_on(db, wazuh_log):
    """It may still be served under other tags, so it keeps the tag it was scanned as."""
    scan_all.ingest(db, "acr/app:latest", F127, host="a", wazuh_log=wazuh_log, eps=0, now=T0,
                    extra={"scanner_mode": "registry", "digest": "sha256:aaa"})
    scan_all.ingest(db, "acr/app:1.1", F128, host="a", wazuh_log=wazuh_log, eps=0, now=T0.replace(hour=5),
                    extra={"scanner_mode": "registry", "digest": "sha256:bbb", "other_tags": "acr/app:latest"})
    assert {s["image"] for s in latest_scans(db)} == {"acr/app:latest", "acr/app:1.1"}


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
