import sys
from pathlib import Path

import mongomock
import mongomock.collection
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _bulk_write(self, requests, ordered=True, **kwargs):
    """mongomock can't take pymongo>=4.11's UpdateOne objects (they carry `sort`).
    Apply them one by one with the same filter/update/upsert semantics."""
    for op in requests:
        self.update_one(op._filter, op._doc, upsert=op._upsert)


mongomock.collection.Collection.bulk_write = _bulk_write


@pytest.fixture
def db():
    return mongomock.MongoClient()["sweri_sbom_test"]


@pytest.fixture
def wazuh_log(tmp_path):
    return str(tmp_path / "trivy-findings.jsonl")
