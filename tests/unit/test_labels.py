"""Every column a table shows has a descriptive header and a hover explanation (plan R1.2).

The test walks the real facade DataFrames, so adding a column to the facade without
naming it in ``sniffdash.ui.labels`` fails here instead of reaching the screen raw.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sniffdash.application import load_capture
from sniffdash.demo import build_http_scenario, build_https_flows, write_pcap
from sniffdash.parsing.extractors.base import Backend
from sniffdash.ui import labels
from sniffdash.ui.views.chat import evidence_frame


@pytest.fixture(scope="module")
def sessions(tmp_path_factory):
    folder = tmp_path_factory.mktemp("c")
    http = write_pcap(folder / "h.pcap", build_http_scenario()).read_bytes()
    https = write_pcap(folder / "s.pcap", build_https_flows()).read_bytes()
    return (load_capture(http, "h.pcap", backend=Backend.SCAPY),
            load_capture(https, "s.pcap", backend=Backend.SCAPY))


def tables(sessions):
    http, https = sessions
    no_evidence = SimpleNamespace(valid_evidence=[])
    return {
        "timeline": (http.timeline_frame(), labels.TIMELINE),
        "protocols": (http.protocol_frame(), labels.PROTOCOLS),
        "sources": (http.talkers_frame("source"), labels.talkers("source")),
        "destinations": (http.talkers_frame("destination"), labels.talkers("destination")),
        "transactions": (http.transactions_frame(), labels.TRANSACTIONS),
        "encrypted": (https.encrypted_frame(), labels.ENCRYPTED),
        "issues": (http.issues_frame(), labels.ISSUES),
        "evidence": (evidence_frame(http, no_evidence), labels.EVIDENCE),
    }


@pytest.mark.parametrize("table", ["timeline", "protocols", "sources", "destinations", "transactions",
                                   "encrypted", "issues", "evidence"])
def test_every_column_is_labelled_and_explained(sessions, table):
    df, config = tables(sessions)[table]
    assert list(df.columns), "the facade frame should have columns"
    for column in df.columns:
        assert column in config, f"{table}.{column} would be shown with its raw name"
        entry = config[column]
        assert entry["label"] != column and len(entry["label"]) > 3, f"{table}.{column}: label is not descriptive"
        assert entry.get("help"), f"{table}.{column}: no hover explanation"


def test_shared_concepts_have_one_name():
    assert labels.TRANSACTIONS["rel_s"]["label"] == labels.EVIDENCE["rel_s"]["label"] == "Seconds since capture start"
