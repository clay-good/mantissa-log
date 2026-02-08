"""Unit tests for the GCP Zeek/Suricata Log Collector Cloud Function."""

import json
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Ensure the GCP functions directory is on the path
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/gcp/functions")
)
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/shared")
)

import gcp_zeek_suricata_collector as collector_module


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


def _make_ndjson_bytes(*events):
    """Create NDJSON bytes from event dicts."""
    return "\n".join(json.dumps(e) for e in events).encode("utf-8")


# ===========================================================================
# Test: _read_gcs_file
# ===========================================================================

class TestReadGCSFile:
    """Tests for GCS file reading."""

    @patch("gcp_zeek_suricata_collector._gcs_storage")
    def test_reads_content(self, mock_storage):
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        content = _make_ndjson_bytes(_ZEEK_CONN)
        mock_blob.download_as_bytes.return_value = content

        result = collector_module._read_gcs_file("test-bucket", "zeek/conn.json")
        assert result == content
        mock_client.bucket.assert_called_with("test-bucket")
        mock_bucket.blob.assert_called_with("zeek/conn.json")

    @patch("gcp_zeek_suricata_collector._gcs_storage")
    def test_failure_returns_empty(self, mock_storage):
        mock_storage.Client.side_effect = Exception("GCS error")
        result = collector_module._read_gcs_file("bucket", "key")
        assert result == b""


# ===========================================================================
# Test: _write_to_gcs
# ===========================================================================

class TestWriteToGCS:
    """Tests for GCS data lake writes."""

    @patch("gcp_zeek_suricata_collector._gcs_storage")
    def test_writes_zeek_ndjson(self, mock_storage):
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        path = collector_module._write_to_gcs(
            [{"a": 1}], "my-bucket", "zeek", ts, "part01"
        )
        assert path == "zeek/raw/2025/06/15/10/zeek_part01.json"
        mock_blob.upload_from_string.assert_called_once()

    @patch("gcp_zeek_suricata_collector._gcs_storage")
    def test_writes_suricata_path(self, mock_storage):
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        path = collector_module._write_to_gcs(
            [{"a": 1}], "my-bucket", "suricata", ts, "part01"
        )
        assert path.startswith("suricata/raw/")

    @patch("gcp_zeek_suricata_collector._gcs_storage")
    def test_empty_events_returns_none(self, mock_storage):
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert collector_module._write_to_gcs([], "bucket", "zeek", ts) is None

    @patch("gcp_zeek_suricata_collector._gcs_storage")
    def test_gcs_failure_returns_none(self, mock_storage):
        mock_storage.Client.side_effect = Exception("GCS error")
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = collector_module._write_to_gcs(
            [{"a": 1}], "bucket", "zeek", ts
        )
        assert result is None


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting and writing."""

    @patch.object(collector_module, "_write_to_gcs")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "path1"
        paths = collector_module._batch_and_write(
            [{"a": 1}], "bucket", "zeek", 10
        )
        assert paths == ["path1"]

    @patch.object(collector_module, "_write_to_gcs")
    def test_multiple_batches(self, mock_write):
        mock_write.side_effect = ["p1", "p2", "p3"]
        events = [{"a": i} for i in range(25)]
        paths = collector_module._batch_and_write(events, "bucket", "zeek", 10)
        assert len(paths) == 3

    @patch.object(collector_module, "_write_to_gcs")
    def test_empty_events(self, mock_write):
        paths = collector_module._batch_and_write([], "bucket", "zeek", 10)
        assert paths == []
        mock_write.assert_not_called()


# ===========================================================================
# Test: _report_health
# ===========================================================================

class TestReportHealth:
    """Tests for health reporting."""

    @patch("src.shared.health.health_state_store.FirestoreHealthStateStore")
    def test_reports_zeek_health(self, mock_store_cls):
        collector_module.HEALTH_STATE_COLLECTION = "health"
        collector_module.TENANT_ID = "t1"
        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        collector_module._report_health(50, "zeek")
        mock_store.update_event_count.assert_called_once()
        assert (
            mock_store.update_event_count.call_args[1]["source_type"] == "zeek"
        )

    @patch("src.shared.health.health_state_store.FirestoreHealthStateStore")
    def test_reports_suricata_health(self, mock_store_cls):
        collector_module.HEALTH_STATE_COLLECTION = "health"
        collector_module.TENANT_ID = "t1"
        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        collector_module._report_health(30, "suricata")
        assert (
            mock_store.update_event_count.call_args[1]["source_type"]
            == "suricata"
        )

    def test_no_health_collection(self):
        collector_module.HEALTH_STATE_COLLECTION = ""
        collector_module._report_health(100, "zeek")  # No crash


# ===========================================================================
# Test: zeek_suricata_gcs (Cloud Event entry point)
# ===========================================================================

class TestZeekSuricataGCS:
    """Tests for the GCS-triggered Cloud Function entry point."""

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    @patch.object(collector_module, "_read_gcs_file")
    def test_processes_zeek_file(self, mock_read, mock_batch, mock_health):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"
        content = _make_ndjson_bytes(_ZEEK_CONN, _ZEEK_DNS)
        mock_read.return_value = content
        mock_batch.return_value = ["path1"]

        cloud_event = SimpleNamespace(
            data={"bucket": "uploads", "name": "zeek/conn.json"}
        )
        result = collector_module.zeek_suricata_gcs(cloud_event)

        assert result["status"] == "success"
        assert result["total_events"] == 2
        assert result["format"] == "zeek"
        mock_health.assert_called_once_with(2, "zeek")

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    @patch.object(collector_module, "_read_gcs_file")
    def test_processes_suricata_file(self, mock_read, mock_batch, mock_health):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"
        content = _make_ndjson_bytes(_SURICATA_ALERT)
        mock_read.return_value = content
        mock_batch.return_value = ["path1"]

        cloud_event = SimpleNamespace(
            data={"bucket": "uploads", "name": "suricata/eve.json"}
        )
        result = collector_module.zeek_suricata_gcs(cloud_event)

        assert result["total_events"] == 1
        assert result["format"] == "suricata"
        mock_health.assert_called_once_with(1, "suricata")

    @patch.object(collector_module, "_read_gcs_file")
    def test_empty_file(self, mock_read):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"
        mock_read.return_value = b""

        cloud_event = SimpleNamespace(
            data={"bucket": "uploads", "name": "empty.json"}
        )
        result = collector_module.zeek_suricata_gcs(cloud_event)
        assert result["total_events"] == 0

    def test_missing_gcs_bucket(self):
        collector_module.GCS_OUTPUT_BUCKET = None
        cloud_event = SimpleNamespace(
            data={"bucket": "uploads", "name": "test.json"}
        )
        result = collector_module.zeek_suricata_gcs(cloud_event)
        assert result["status"] == "error"

    def test_missing_bucket_or_blob(self):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"
        cloud_event = SimpleNamespace(data={"bucket": "", "name": ""})
        result = collector_module.zeek_suricata_gcs(cloud_event)
        assert result["status"] == "error"

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    @patch.object(collector_module, "_read_gcs_file")
    def test_no_parseable_events(self, mock_read, mock_batch, mock_health):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"
        mock_read.return_value = b"not json\nnot json either\n"

        cloud_event = SimpleNamespace(
            data={"bucket": "uploads", "name": "bad.json"}
        )
        result = collector_module.zeek_suricata_gcs(cloud_event)
        assert result["total_events"] == 0
        mock_health.assert_not_called()


# ===========================================================================
# Test: zeek_suricata_http (HTTP entry point)
# ===========================================================================

class TestZeekSuricataHTTP:
    """Tests for the HTTP Cloud Function entry point."""

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    @patch.object(collector_module, "_read_gcs_file")
    def test_processes_request(self, mock_read, mock_batch, mock_health):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"
        content = _make_ndjson_bytes(_ZEEK_CONN)
        mock_read.return_value = content
        mock_batch.return_value = ["path1"]

        request = MagicMock()
        request.get_json.return_value = {
            "bucket": "uploads",
            "name": "zeek/conn.json",
        }
        result = collector_module.zeek_suricata_http(request)
        assert result["status"] == "success"
        assert result["total_events"] == 1

    def test_missing_gcs_bucket(self):
        collector_module.GCS_OUTPUT_BUCKET = None
        request = MagicMock()
        result = collector_module.zeek_suricata_http(request)
        assert result[0]["status"] == "error"

    def test_invalid_request(self):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"
        request = MagicMock()
        request.get_json.return_value = None
        result = collector_module.zeek_suricata_http(request)
        assert result[0]["status"] == "error"

    def test_missing_bucket_or_name(self):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"
        request = MagicMock()
        request.get_json.return_value = {"bucket": "", "name": ""}
        result = collector_module.zeek_suricata_http(request)
        assert result[0]["status"] == "error"


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests."""

    @patch("gcp_zeek_suricata_collector._gcs_storage")
    @patch.object(collector_module, "_report_health")
    def test_gcs_trigger_full_pipeline(self, mock_health, mock_storage):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"

        # Mock GCS for read
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket_read = MagicMock()
        mock_bucket_write = MagicMock()

        content = _make_ndjson_bytes(_ZEEK_CONN, _ZEEK_DNS)

        def _bucket_router(name):
            if name == "uploads":
                return mock_bucket_read
            return mock_bucket_write

        mock_client.bucket.side_effect = _bucket_router

        mock_blob_read = MagicMock()
        mock_blob_read.download_as_bytes.return_value = content
        mock_bucket_read.blob.return_value = mock_blob_read

        mock_blob_write = MagicMock()
        mock_bucket_write.blob.return_value = mock_blob_write

        cloud_event = SimpleNamespace(
            data={"bucket": "uploads", "name": "zeek/conn.json"}
        )
        result = collector_module.zeek_suricata_gcs(cloud_event)

        assert result["total_events"] == 2
        assert result["format"] == "zeek"
        assert result["files_written"] == 1
        mock_blob_write.upload_from_string.assert_called_once()

        written = mock_blob_write.upload_from_string.call_args[0][0]
        lines = written.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "source_ip" in parsed

    @patch("gcp_zeek_suricata_collector._gcs_storage")
    @patch.object(collector_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_storage):
        collector_module.GCS_OUTPUT_BUCKET = "test-lake"

        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket_read = MagicMock()
        mock_bucket_write = MagicMock()

        content = _make_ndjson_bytes(_SURICATA_ALERT)

        def _bucket_router(name):
            if name == "uploads":
                return mock_bucket_read
            return mock_bucket_write

        mock_client.bucket.side_effect = _bucket_router

        mock_blob_read = MagicMock()
        mock_blob_read.download_as_bytes.return_value = content
        mock_bucket_read.blob.return_value = mock_blob_read

        mock_blob_write = MagicMock()
        mock_bucket_write.blob.return_value = mock_blob_write

        cloud_event = SimpleNamespace(
            data={"bucket": "uploads", "name": "suricata/eve.json"}
        )
        collector_module.zeek_suricata_gcs(cloud_event)

        blob_path = mock_bucket_write.blob.call_args[0][0]
        assert blob_path.startswith("suricata/raw/")
        parts = blob_path.split("/")
        assert parts[0] == "suricata"
        assert parts[1] == "raw"
