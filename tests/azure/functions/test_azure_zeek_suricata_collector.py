"""Unit tests for the Azure Zeek/Suricata Log Collector."""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# Ensure the Azure functions directory is on the path
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/azure/functions")
)
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/shared")
)

import azure_zeek_suricata_collector as collector_module


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
# Test: _write_to_blob
# ===========================================================================

class TestWriteToBlob:
    """Tests for Blob Storage writes."""

    @patch("azure_zeek_suricata_collector.BlobServiceClient")
    def test_writes_zeek_ndjson(self, mock_blob_cls):
        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        path = collector_module._write_to_blob(
            [{"a": 1}], "conn-str", "container", "zeek", ts, "part01"
        )
        assert path == "zeek/raw/2025/06/15/10/zeek_part01.json"
        mock_blob.upload_blob.assert_called_once()

    @patch("azure_zeek_suricata_collector.BlobServiceClient")
    def test_writes_suricata_path(self, mock_blob_cls):
        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        path = collector_module._write_to_blob(
            [{"a": 1}], "conn-str", "container", "suricata", ts, "part01"
        )
        assert path.startswith("suricata/raw/")

    @patch("azure_zeek_suricata_collector.BlobServiceClient")
    def test_empty_events_returns_none(self, mock_blob_cls):
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert (
            collector_module._write_to_blob(
                [], "conn-str", "container", "zeek", ts
            )
            is None
        )

    @patch("azure_zeek_suricata_collector.BlobServiceClient")
    def test_blob_failure_returns_none(self, mock_blob_cls):
        mock_blob_cls.from_connection_string.side_effect = Exception(
            "Blob error"
        )
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = collector_module._write_to_blob(
            [{"a": 1}], "conn", "cont", "zeek", ts
        )
        assert result is None


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting and writing."""

    @patch.object(collector_module, "_write_to_blob")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "path1"
        paths = collector_module._batch_and_write(
            [{"a": 1}], "conn-str", "container", "zeek", 10
        )
        assert paths == ["path1"]

    @patch.object(collector_module, "_write_to_blob")
    def test_multiple_batches(self, mock_write):
        mock_write.side_effect = ["p1", "p2", "p3"]
        events = [{"a": i} for i in range(25)]
        paths = collector_module._batch_and_write(
            events, "conn-str", "container", "zeek", 10
        )
        assert len(paths) == 3

    @patch.object(collector_module, "_write_to_blob")
    def test_empty_events(self, mock_write):
        paths = collector_module._batch_and_write(
            [], "conn-str", "container", "zeek", 10
        )
        assert paths == []
        mock_write.assert_not_called()


# ===========================================================================
# Test: _report_health
# ===========================================================================

class TestReportHealth:
    """Tests for health reporting."""

    @patch("src.shared.health.health_state_store.CosmosHealthStateStore")
    def test_reports_zeek_health(self, mock_store_cls):
        collector_module.COSMOS_ENDPOINT = "https://cosmos.test"
        collector_module.COSMOS_KEY = "key"
        collector_module.COSMOS_HEALTH_CONTAINER = "health"
        collector_module.TENANT_ID = "t1"

        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        collector_module._report_health(50, "zeek")
        mock_store.update_event_count.assert_called_once()
        assert (
            mock_store.update_event_count.call_args[1]["source_type"] == "zeek"
        )

    @patch("src.shared.health.health_state_store.CosmosHealthStateStore")
    def test_reports_suricata_health(self, mock_store_cls):
        collector_module.COSMOS_ENDPOINT = "https://cosmos.test"
        collector_module.COSMOS_KEY = "key"
        collector_module.COSMOS_HEALTH_CONTAINER = "health"
        collector_module.TENANT_ID = "t1"

        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        collector_module._report_health(30, "suricata")
        assert (
            mock_store.update_event_count.call_args[1]["source_type"]
            == "suricata"
        )

    def test_no_cosmos_endpoint(self):
        collector_module.COSMOS_ENDPOINT = ""
        collector_module.COSMOS_HEALTH_CONTAINER = ""
        collector_module._report_health(100, "zeek")  # No crash


# ===========================================================================
# Test: blob_trigger
# ===========================================================================

class TestBlobTrigger:
    """Tests for the Blob Storage trigger entry point."""

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_zeek_file(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        content = _make_ndjson_bytes(_ZEEK_CONN, _ZEEK_DNS)
        result = collector_module.blob_trigger(content, "zeek/conn.json")

        assert result["status"] == "success"
        assert result["total_events"] == 2
        assert result["format"] == "zeek"
        mock_health.assert_called_once_with(2, "zeek")

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_suricata_file(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        content = _make_ndjson_bytes(_SURICATA_ALERT)
        result = collector_module.blob_trigger(content, "suricata/eve.json")

        assert result["total_events"] == 1
        assert result["format"] == "suricata"
        mock_health.assert_called_once_with(1, "suricata")

    def test_empty_content(self):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        result = collector_module.blob_trigger(b"", "empty.json")
        assert result["total_events"] == 0

    def test_missing_connection_string(self):
        collector_module.STORAGE_CONNECTION_STRING = ""
        result = collector_module.blob_trigger(
            _make_ndjson_bytes(_ZEEK_CONN), "test.json"
        )
        assert result["status"] == "error"

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_unparseable_content(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        result = collector_module.blob_trigger(
            b"not json\nnot json either\n", "bad.json"
        )
        assert result["total_events"] == 0
        mock_health.assert_not_called()

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_blob_name_in_result(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        content = _make_ndjson_bytes(_ZEEK_CONN)
        result = collector_module.blob_trigger(content, "sensors/zeek/conn.json")
        assert result["source_blob"] == "sensors/zeek/conn.json"


# ===========================================================================
# Test: http_trigger
# ===========================================================================

class TestHttpTrigger:
    """Tests for the HTTP trigger entry point."""

    @patch("azure_zeek_suricata_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_request(self, mock_batch, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_blob = MagicMock()
        mock_service.get_blob_client.return_value = mock_blob
        mock_download = MagicMock()
        mock_download.readall.return_value = _make_ndjson_bytes(_ZEEK_CONN)
        mock_blob.download_blob.return_value = mock_download

        result = collector_module.http_trigger(
            {"container": "uploads", "blob_name": "zeek/conn.json"}
        )
        assert result["status"] == "success"
        assert result["total_events"] == 1

    def test_missing_connection_string(self):
        collector_module.STORAGE_CONNECTION_STRING = ""
        result = collector_module.http_trigger(
            {"container": "c", "blob_name": "b"}
        )
        assert result["status"] == "error"

    def test_missing_container_or_blob(self):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        result = collector_module.http_trigger({"container": "", "blob_name": ""})
        assert result["status"] == "error"
        assert result["error"] == "missing_container_or_blob"

    @patch("azure_zeek_suricata_collector.BlobServiceClient")
    def test_blob_read_failure(self, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_service.get_blob_client.side_effect = Exception("Read error")

        result = collector_module.http_trigger(
            {"container": "c", "blob_name": "b"}
        )
        assert result["status"] == "error"
        assert result["error"] == "blob_read_failed"


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests."""

    @patch("azure_zeek_suricata_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    def test_blob_trigger_full_pipeline(self, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        collector_module.OUTPUT_CONTAINER = "mantissa-logs"

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        content = _make_ndjson_bytes(_ZEEK_CONN, _ZEEK_DNS)
        result = collector_module.blob_trigger(content, "zeek/conn.json")

        assert result["total_events"] == 2
        assert result["format"] == "zeek"
        assert result["files_written"] == 1
        mock_blob.upload_blob.assert_called_once()

        written = mock_blob.upload_blob.call_args[0][0]
        lines = written.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "source_ip" in parsed

    @patch("azure_zeek_suricata_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        collector_module.OUTPUT_CONTAINER = "mantissa-logs"

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        content = _make_ndjson_bytes(_SURICATA_ALERT)
        collector_module.blob_trigger(content, "suricata/eve.json")

        blob_path = mock_container.get_blob_client.call_args[0][0]
        assert blob_path.startswith("suricata/raw/")
        parts = blob_path.split("/")
        assert parts[0] == "suricata"
        assert parts[1] == "raw"

    @patch("azure_zeek_suricata_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    def test_suricata_full_pipeline(self, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        collector_module.OUTPUT_CONTAINER = "mantissa-logs"

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        content = _make_ndjson_bytes(_SURICATA_ALERT)
        result = collector_module.blob_trigger(content, "suricata/eve.json")

        assert result["total_events"] == 1
        assert result["format"] == "suricata"
        mock_blob.upload_blob.assert_called_once()

        written = mock_blob.upload_blob.call_args[0][0]
        parsed = json.loads(written.strip())
        assert "alert" in parsed["metadata"]["tags"]
