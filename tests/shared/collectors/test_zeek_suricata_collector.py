"""Unit tests for the Zeek/Suricata on-prem collector."""

import json
import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.shared.collectors.zeek_suricata_collector import (
    FileState,
    ZeekSuricataCollector,
    detect_format,
    parse_event,
    parse_uploaded_file,
    write_local,
    _load_state,
    _save_state,
    _detect_rotation,
    _read_new_lines,
    _parse_lines,
)


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_ZEEK_CONN = {
    "_path": "conn",
    "ts": 1718442000.0,
    "uid": "CYIoD3dLMjzQpghga",
    "id.orig_h": "10.0.0.4",
    "id.orig_p": 54321,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 443,
    "proto": "tcp",
    "conn_state": "SF",
    "duration": 2.5,
    "orig_bytes": 1200,
    "resp_bytes": 5600,
}

_ZEEK_DNS = {
    "_path": "dns",
    "ts": 1718442001.0,
    "uid": "CDNS123",
    "id.orig_h": "10.0.0.5",
    "id.orig_p": 12345,
    "id.resp_h": "8.8.8.8",
    "id.resp_p": 53,
    "proto": "udp",
    "query": "api.example.com",
    "qtype_name": "A",
    "rcode_name": "NOERROR",
    "answers": ["93.184.216.34"],
}

_SURICATA_ALERT = {
    "timestamp": "2025-06-15T10:00:00.000000+0000",
    "event_type": "alert",
    "src_ip": "10.0.0.4",
    "src_port": 54321,
    "dest_ip": "93.184.216.34",
    "dest_port": 443,
    "proto": "TCP",
    "alert": {
        "action": "blocked",
        "signature_id": 2024897,
        "rev": 1,
        "signature": "ET MALWARE Bad SSL Cert",
        "category": "A Network Trojan was Detected",
        "severity": 1,
    },
}

_SURICATA_FLOW = {
    "timestamp": "2025-06-15T10:01:00.000000+0000",
    "event_type": "flow",
    "src_ip": "10.0.0.5",
    "src_port": 12345,
    "dest_ip": "8.8.8.8",
    "dest_port": 53,
    "proto": "UDP",
    "flow": {
        "pkts_toserver": 1,
        "pkts_toclient": 1,
        "bytes_toserver": 60,
        "bytes_toclient": 120,
        "start": "2025-06-15T10:00:58.000000+0000",
        "end": "2025-06-15T10:01:00.000000+0000",
    },
}


# ===========================================================================
# Test: detect_format
# ===========================================================================

class TestDetectFormat:
    """Tests for format auto-detection."""

    def test_zeek_path_field(self):
        assert detect_format({"_path": "conn", "ts": 1.0}) == "zeek"

    def test_suricata_event_type(self):
        assert detect_format({"event_type": "alert"}) == "suricata"

    def test_zeek_id_fields(self):
        assert detect_format({"id": {"orig_h": "1.2.3.4"}}) == "zeek"

    def test_zeek_conn_state(self):
        assert detect_format({"conn_state": "SF"}) == "zeek"

    def test_zeek_uid_ts(self):
        assert detect_format({"uid": "abc", "ts": 1.0}) == "zeek"

    def test_suricata_alert_object(self):
        assert detect_format({"alert": {"signature_id": 123}}) == "suricata"

    def test_suricata_flow_id(self):
        assert detect_format({"flow_id": 12345}) == "suricata"

    def test_unknown(self):
        assert detect_format({"random": "data"}) is None

    def test_non_dict(self):
        assert detect_format("not a dict") is None

    def test_full_zeek_conn(self):
        assert detect_format(_ZEEK_CONN) == "zeek"

    def test_full_suricata_alert(self):
        assert detect_format(_SURICATA_ALERT) == "suricata"


# ===========================================================================
# Test: parse_event
# ===========================================================================

class TestParseEvent:
    """Tests for single event parsing."""

    def test_parse_zeek_conn(self):
        result = parse_event(_ZEEK_CONN)
        assert result is not None
        assert result["source_ip"] == "10.0.0.4"
        assert "network" in result["metadata"]["tags"]

    def test_parse_zeek_dns(self):
        result = parse_event(_ZEEK_DNS)
        assert result is not None
        assert "dns" in result["metadata"]["tags"]

    def test_parse_suricata_alert(self):
        result = parse_event(_SURICATA_ALERT)
        assert result is not None
        assert result["source_ip"] == "10.0.0.4"
        assert "alert" in result["metadata"]["tags"]

    def test_parse_suricata_flow(self):
        result = parse_event(_SURICATA_FLOW)
        assert result is not None

    def test_parse_with_hint(self):
        result = parse_event(_ZEEK_CONN, format_hint="zeek")
        assert result is not None

    def test_parse_unknown(self):
        assert parse_event({"random": "data"}) is None


# ===========================================================================
# Test: FileState
# ===========================================================================

class TestFileState:
    """Tests for FileState serialization."""

    def test_to_dict(self):
        state = FileState(
            path="/var/log/zeek.log", offset=1024, inode=12345,
            size=2048, last_modified=1000.0, fmt="zeek",
        )
        d = state.to_dict()
        assert d["path"] == "/var/log/zeek.log"
        assert d["offset"] == 1024
        assert d["format"] == "zeek"

    def test_from_dict(self):
        d = {
            "path": "/var/log/suricata.json",
            "offset": 512,
            "inode": 99,
            "size": 1024,
            "last_modified": 500.0,
            "format": "suricata",
        }
        state = FileState.from_dict(d)
        assert state.path == "/var/log/suricata.json"
        assert state.fmt == "suricata"

    def test_roundtrip(self):
        state = FileState(
            path="/test", offset=100, inode=1, size=200,
            last_modified=300.0, fmt="zeek",
        )
        restored = FileState.from_dict(state.to_dict())
        assert restored.path == state.path
        assert restored.offset == state.offset
        assert restored.fmt == state.fmt


# ===========================================================================
# Test: State persistence
# ===========================================================================

class TestStatePersistence:
    """Tests for state file load/save."""

    def test_save_and_load(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            state_file = f.name

        try:
            states = {
                "/log/a.json": FileState("/log/a.json", 100, 1, 200, 300.0, "zeek"),
                "/log/b.json": FileState("/log/b.json", 50, 2, 100, 150.0, "suricata"),
            }
            _save_state(state_file, states)
            loaded = _load_state(state_file)
            assert len(loaded) == 2
            assert loaded["/log/a.json"].fmt == "zeek"
            assert loaded["/log/b.json"].offset == 50
        finally:
            os.unlink(state_file)

    def test_load_nonexistent(self):
        assert _load_state("/nonexistent/state.json") == {}

    def test_load_corrupted(self):
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            f.write("not json")
            state_file = f.name

        try:
            assert _load_state(state_file) == {}
        finally:
            os.unlink(state_file)


# ===========================================================================
# Test: Rotation detection
# ===========================================================================

class TestRotationDetection:
    """Tests for log rotation detection."""

    def test_different_inode(self):
        state = FileState("/log", offset=100, inode=1, size=200)
        assert _detect_rotation(state, inode=2, size=200) is True

    def test_smaller_size(self):
        state = FileState("/log", offset=100, inode=1, size=200)
        assert _detect_rotation(state, inode=1, size=50) is True

    def test_no_rotation(self):
        state = FileState("/log", offset=100, inode=1, size=200)
        assert _detect_rotation(state, inode=1, size=300) is False

    def test_zero_inode(self):
        state = FileState("/log", offset=100, inode=0, size=200)
        assert _detect_rotation(state, inode=5, size=200) is False


# ===========================================================================
# Test: _read_new_lines
# ===========================================================================

class TestReadNewLines:
    """Tests for incremental file reading."""

    def test_read_from_start(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write('{"a": 1}\n{"b": 2}\n')
            path = f.name

        try:
            lines, offset = _read_new_lines(path, 0)
            assert len(lines) == 2
            assert offset > 0
        finally:
            os.unlink(path)

    def test_read_incremental(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write('{"a": 1}\n')
            path = f.name
            first_size = f.tell()

        try:
            with open(path, "a") as f:
                f.write('{"b": 2}\n')

            lines, offset = _read_new_lines(path, first_size)
            assert len(lines) == 1
            assert '{"b": 2}' in lines[0]
        finally:
            os.unlink(path)


# ===========================================================================
# Test: _parse_lines
# ===========================================================================

class TestParseLines:
    """Tests for JSON line parsing."""

    def test_parse_zeek_lines(self):
        lines = [json.dumps(_ZEEK_CONN)]
        events, fmt = _parse_lines(lines)
        assert len(events) == 1
        assert fmt == "zeek"

    def test_parse_suricata_lines(self):
        lines = [json.dumps(_SURICATA_ALERT)]
        events, fmt = _parse_lines(lines)
        assert len(events) == 1
        assert fmt == "suricata"

    def test_parse_mixed_invalid(self):
        lines = [json.dumps(_ZEEK_CONN), "not json", ""]
        events, fmt = _parse_lines(lines)
        assert len(events) == 1

    def test_empty_lines(self):
        events, fmt = _parse_lines([])
        assert events == []
        assert fmt is None

    def test_format_hint(self):
        lines = [json.dumps(_ZEEK_CONN)]
        events, fmt = _parse_lines(lines, format_hint="zeek")
        assert len(events) == 1
        assert fmt == "zeek"


# ===========================================================================
# Test: write_local
# ===========================================================================

class TestWriteLocal:
    """Tests for local output writing."""

    def test_writes_ndjson(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            events = [parse_event(_ZEEK_CONN)]
            ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
            path = write_local(events, tmpdir, "zeek", ts)

            assert path is not None
            assert "zeek/raw/2025/06/15/10/" in path
            assert os.path.exists(path)

            with open(path) as f:
                content = f.read()
            assert len(content.strip().split("\n")) == 1

    def test_empty_events(self):
        assert write_local([], "/tmp", "zeek") is None


# ===========================================================================
# Test: parse_uploaded_file
# ===========================================================================

class TestParseUploadedFile:
    """Tests for cloud upload file parsing."""

    def test_parse_zeek_file(self):
        content = "\n".join(
            [json.dumps(_ZEEK_CONN), json.dumps(_ZEEK_DNS)]
        ).encode("utf-8")
        events, fmt = parse_uploaded_file(content)
        assert len(events) == 2
        assert fmt == "zeek"

    def test_parse_suricata_file(self):
        content = "\n".join(
            [json.dumps(_SURICATA_ALERT), json.dumps(_SURICATA_FLOW)]
        ).encode("utf-8")
        events, fmt = parse_uploaded_file(content)
        assert len(events) == 2
        assert fmt == "suricata"

    def test_empty_content(self):
        events, fmt = parse_uploaded_file(b"")
        assert events == []

    def test_invalid_json(self):
        events, fmt = parse_uploaded_file(b"not json\nstill not json\n")
        assert events == []


# ===========================================================================
# Test: ZeekSuricataCollector
# ===========================================================================

class TestZeekSuricataCollector:
    """Tests for the on-prem collector class."""

    def test_collect_zeek_files(self):
        with tempfile.TemporaryDirectory() as watch_dir:
            with tempfile.TemporaryDirectory() as output_dir:
                # Write a Zeek log file
                log_path = os.path.join(watch_dir, "conn.json")
                with open(log_path, "w") as f:
                    f.write(json.dumps(_ZEEK_CONN) + "\n")
                    f.write(json.dumps(_ZEEK_DNS) + "\n")

                collector = ZeekSuricataCollector(
                    watch_dirs=[watch_dir],
                    output_dir=output_dir,
                    state_dir=output_dir,
                )
                result = collector.collect()

                assert result["status"] == "success"
                assert result["total_events"] == 2
                assert result["formats"].get("zeek", 0) == 2
                assert len(result["output_paths"]) >= 1

    def test_collect_suricata_files(self):
        with tempfile.TemporaryDirectory() as watch_dir:
            with tempfile.TemporaryDirectory() as output_dir:
                log_path = os.path.join(watch_dir, "eve.json")
                with open(log_path, "w") as f:
                    f.write(json.dumps(_SURICATA_ALERT) + "\n")

                collector = ZeekSuricataCollector(
                    watch_dirs=[watch_dir],
                    output_dir=output_dir,
                    state_dir=output_dir,
                )
                result = collector.collect()

                assert result["total_events"] == 1
                assert result["formats"].get("suricata", 0) == 1

    def test_incremental_reading(self):
        with tempfile.TemporaryDirectory() as watch_dir:
            with tempfile.TemporaryDirectory() as output_dir:
                log_path = os.path.join(watch_dir, "conn.json")
                with open(log_path, "w") as f:
                    f.write(json.dumps(_ZEEK_CONN) + "\n")

                collector = ZeekSuricataCollector(
                    watch_dirs=[watch_dir],
                    output_dir=output_dir,
                    state_dir=output_dir,
                )

                # First run: reads 1 event
                result1 = collector.collect()
                assert result1["total_events"] == 1

                # Second run: no new data
                result2 = collector.collect()
                assert result2["total_events"] == 0

                # Add more data
                with open(log_path, "a") as f:
                    f.write(json.dumps(_ZEEK_DNS) + "\n")

                # Third run: reads new event
                result3 = collector.collect()
                assert result3["total_events"] == 1

    def test_empty_watch_directory(self):
        with tempfile.TemporaryDirectory() as watch_dir:
            with tempfile.TemporaryDirectory() as output_dir:
                collector = ZeekSuricataCollector(
                    watch_dirs=[watch_dir],
                    output_dir=output_dir,
                    state_dir=output_dir,
                )
                result = collector.collect()
                assert result["total_events"] == 0

    def test_nonexistent_watch_directory(self):
        with tempfile.TemporaryDirectory() as output_dir:
            collector = ZeekSuricataCollector(
                watch_dirs=["/nonexistent/path"],
                output_dir=output_dir,
                state_dir=output_dir,
            )
            result = collector.collect()
            assert result["total_events"] == 0

    def test_upload_fn_callback(self):
        mock_upload = MagicMock(return_value="s3://bucket/key")

        with tempfile.TemporaryDirectory() as watch_dir:
            with tempfile.TemporaryDirectory() as state_dir:
                log_path = os.path.join(watch_dir, "conn.json")
                with open(log_path, "w") as f:
                    f.write(json.dumps(_ZEEK_CONN) + "\n")

                collector = ZeekSuricataCollector(
                    watch_dirs=[watch_dir],
                    state_dir=state_dir,
                    upload_fn=mock_upload,
                )
                result = collector.collect()

                assert result["total_events"] == 1
                mock_upload.assert_called_once()
