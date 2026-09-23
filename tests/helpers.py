import json
import os
from datetime import datetime, timedelta, timezone

import scan_all
from conftest import FIXTURES

T0 = datetime(2026, 9, 20, 2, 30, tzinfo=timezone.utc)
F127 = FIXTURES / "app_debian12.7.cdx.json"   # example/app:1.0 built on Debian 12.7
F128 = FIXTURES / "app_debian12.8.cdx.json"   # the same image rebuilt on Debian 12.8
IMG = "example/app:1.0"
BASELINE_EVENTS = 15                           # 8 packages (incl. the OS) + 7 CVE/package pairs


def read_events(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


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
