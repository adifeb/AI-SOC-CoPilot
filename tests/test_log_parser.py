"""Tests for multi-format ingestion, timestamp normalization, and refs."""

from src.log_parser import normalize_timestamp


def test_all_eight_sources_parse(events):
    sources = {e.log_source for e in events}
    assert sources == {
        "windows", "syslog", "apache", "suricata", "zeek", "cloudtrail", "okta", "defender"
    }


def test_every_event_has_a_ref_in_order(events):
    refs = [e.ref for e in events]
    assert refs[0] == "EVT-0001"
    assert refs == [f"EVT-{i:04d}" for i in range(1, len(events) + 1)]


def test_timeline_is_chronological(events):
    dts = [e.dt for e in events]
    assert all(d is not None for d in dts)
    assert dts == sorted(dts)


def test_shared_iocs_span_multiple_sources(events):
    def sources_for(ioc):
        return {e.log_source for e in events if ioc in e.description or ioc in e.raw_message}

    assert len(sources_for("203.0.113.45")) >= 2
    assert len(sources_for("198.51.100.200")) >= 2


def test_normalize_timestamp_handles_formats():
    assert normalize_timestamp("2026-05-31T15:30:05Z", "windows", 2026).year == 2026
    assert normalize_timestamp("31/May/2026:10:00:12 +0000", "apache", 2026).day == 31
    assert normalize_timestamp("May 28 02:10:11", "syslog", 2026).year == 2026
    assert normalize_timestamp("2026-05-29T23:41:35.120000+0000", "suricata", 2026).minute == 41
    assert normalize_timestamp("garbage", "x", 2026) is None


def test_high_signal_events_are_classified(events):
    types = {e.event_type for e in events}
    # The worst activity must not be buried as generic "system_event".
    for expected in ("data_exfiltration", "c2_beacon", "webshell_access"):
        assert expected in types
