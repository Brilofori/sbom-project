import json

import pytest

import export_cyclonedx
from helpers import F127, F128, run
from sbom_common import latest_scans


def test_latest_scans_is_per_host_and_image(db, wazuh_log):
    run(db, F127, wazuh_log, 0, host="a")
    run(db, F128, wazuh_log, 1, host="a")
    run(db, F127, wazuh_log, 2, host="b")
    latest = {(s["host"], s["image_id"][-1]) for s in latest_scans(db)}
    assert latest == {("a", "2"), ("b", "1")}


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
