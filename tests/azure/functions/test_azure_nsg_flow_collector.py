"""Unit tests for the Azure NSG Flow Log Collector."""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# Ensure the Azure functions directory is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/azure/functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/shared"))

import azure_nsg_flow_collector as collector_module


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_SAMPLE_NSG_RECORD = {
    "time": "2025-06-15T10:00:00.0000000Z",
    "systemId": "abc123",
    "macAddress": "001122334455",
    "category": "NetworkSecurityGroupFlowEvent",
    "resourceId": "/SUBSCRIPTIONS/sub123/RESOURCEGROUPS/rg1/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/nsg1",
    "operationName": "NetworkSecurityGroupFlowEvents",
    "properties": {
        "Version": 2,
        "flows": [
            {
                "rule": "DefaultRule_AllowInternetOutBound",
                "flows": [
                    {
                        "mac": "001122334455",
                        "flowTuples": [
                            "1718445600,10.0.0.4,93.184.216.34,54321,443,T,O,A,B,10,1234,5,678",
                            "1718445610,10.0.0.4,93.184.216.34,54321,443,T,O,A,E,20,2468,10,1356",
                        ],
                    }
                ],
            }
        ],
    },
}

_SAMPLE_NSG_RECORD_V1 = {
    "time": "2025-06-15T10:01:00.0000000Z",
    "systemId": "def456",
    "macAddress": "AABBCCDDEEFF",
    "category": "NetworkSecurityGroupFlowEvent",
    "resourceId": "/SUBSCRIPTIONS/sub123/RESOURCEGROUPS/rg1/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/nsg2",
    "operationName": "NetworkSecurityGroupFlowEvents",
    "properties": {
        "Version": 1,
        "flows": [
            {
                "rule": "UserRule_AllowSSH",
                "flows": [
                    {
                        "mac": "AABBCCDDEEFF",
                        "flowTuples": [
                            "1718445660,192.168.1.5,10.0.0.10,12345,22,T,I,A",
                        ],
                    }
                ],
            }
        ],
    },
}

_SAMPLE_NSG_FILE = {
    "records": [_SAMPLE_NSG_RECORD, _SAMPLE_NSG_RECORD_V1],
}

_SAMPLE_BLOB_PATH = (
    "resourceId=/SUBSCRIPTIONS/sub123/RESOURCEGROUPS/rg1/"
    "PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/nsg1/"
    "y=2025/m=06/d=15/h=10/m=00/macAddress=001122334455/PT1H.json"
)


# ===========================================================================
# Test: _read_nsg_flow_file
# ===========================================================================

class TestReadNSGFlowFile:
    """Tests for NSG flow file reading."""

    def test_reads_records(self):
        content = json.dumps(_SAMPLE_NSG_FILE).encode("utf-8")
        records = collector_module._read_nsg_flow_file(content)
        assert len(records) == 2

    def test_empty_records(self):
        content = json.dumps({"records": []}).encode("utf-8")
        records = collector_module._read_nsg_flow_file(content)
        assert records == []

    def test_invalid_json(self):
        records = collector_module._read_nsg_flow_file(b"not json")
        assert records == []

    def test_missing_records_key(self):
        content = json.dumps({"other": "data"}).encode("utf-8")
        records = collector_module._read_nsg_flow_file(content)
        assert records == []


# ===========================================================================
# Test: _parse_nsg_records
# ===========================================================================

class TestParseNSGRecords:
    """Tests for NSG record parsing."""

    def test_parse_v2_record(self):
        events = collector_module._parse_nsg_records([_SAMPLE_NSG_RECORD])
        assert len(events) >= 1
        event = events[0]
        assert event["source_ip"] == "10.0.0.4"
        assert event["destination_ip"] == "93.184.216.34"
        assert "network" in event["metadata"]["tags"]

    def test_parse_v1_record(self):
        events = collector_module._parse_nsg_records([_SAMPLE_NSG_RECORD_V1])
        assert len(events) >= 1

    def test_parse_multiple_records(self):
        events = collector_module._parse_nsg_records([
            _SAMPLE_NSG_RECORD,
            _SAMPLE_NSG_RECORD_V1,
        ])
        assert len(events) >= 3  # 2 tuples from v2 + 1 from v1

    def test_invalid_records_skipped(self):
        events = collector_module._parse_nsg_records([
            _SAMPLE_NSG_RECORD,
            {"not": "nsg data"},
        ])
        assert len(events) >= 1

    def test_empty_input(self):
        assert collector_module._parse_nsg_records([]) == []

    def test_parsed_event_structure(self):
        events = collector_module._parse_nsg_records([_SAMPLE_NSG_RECORD])
        event = events[0]
        for key in ("timestamp", "source_ip", "destination_ip", "action", "result", "service", "metadata", "raw_event"):
            assert key in event


# ===========================================================================
# Test: _extract_blob_metadata
# ===========================================================================

class TestExtractBlobMetadata:
    """Tests for blob path metadata extraction."""

    def test_full_path(self):
        meta = collector_module._extract_blob_metadata(_SAMPLE_BLOB_PATH)
        assert meta["subscription_id"] == "SUB123"
        assert meta["resource_group"] == "RG1"
        assert meta["nsg_name"] == "NSG1"
        assert meta["year"] == "2025"
        assert meta["month"] == "06"
        assert meta["day"] == "15"
        assert meta["hour"] == "10"
        assert meta["mac_address"] == "001122334455"

    def test_minimal_path(self):
        meta = collector_module._extract_blob_metadata("some/simple/path.json")
        assert "subscription_id" not in meta
        assert "nsg_name" not in meta


# ===========================================================================
# Test: _write_to_blob
# ===========================================================================

class TestWriteToBlob:
    """Tests for Blob Storage writes."""

    @patch("azure_nsg_flow_collector.BlobServiceClient")
    def test_writes_ndjson(self, mock_blob_cls):
        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        events = collector_module._parse_nsg_records([_SAMPLE_NSG_RECORD])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

        path = collector_module._write_to_blob(events, "conn-str", "container", ts, "part01")
        assert path == "azure_nsg_flow/raw/2025/06/15/10/nsg_part01.json"
        mock_blob.upload_blob.assert_called_once()

    @patch("azure_nsg_flow_collector.BlobServiceClient")
    def test_empty_events_returns_none(self, mock_blob_cls):
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert collector_module._write_to_blob([], "conn-str", "container", ts) is None

    @patch("azure_nsg_flow_collector.BlobServiceClient")
    def test_blob_failure_returns_none(self, mock_blob_cls):
        mock_blob_cls.from_connection_string.side_effect = Exception("Blob error")
        events = collector_module._parse_nsg_records([_SAMPLE_NSG_RECORD])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert collector_module._write_to_blob(events, "conn-str", "container", ts) is None


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting and writing."""

    @patch.object(collector_module, "_write_to_blob")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "path1"
        paths = collector_module._batch_and_write([{"a": 1}], "conn", "cont", 10)
        assert paths == ["path1"]

    @patch.object(collector_module, "_write_to_blob")
    def test_multiple_batches(self, mock_write):
        mock_write.side_effect = ["p1", "p2", "p3"]
        events = [{"a": i} for i in range(25)]
        paths = collector_module._batch_and_write(events, "conn", "cont", 10)
        assert len(paths) == 3


# ===========================================================================
# Test: _report_health
# ===========================================================================

class TestReportHealth:
    """Tests for health reporting."""

    @patch("src.shared.health.health_state_store.CosmosHealthStateStore")
    def test_reports_health(self, mock_store_cls):
        collector_module.COSMOS_ENDPOINT = "https://cosmos.test"
        collector_module.COSMOS_KEY = "key"
        collector_module.COSMOS_HEALTH_CONTAINER = "health"
        collector_module.TENANT_ID = "t1"

        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        collector_module._report_health(50)
        mock_store.update_event_count.assert_called_once()
        assert mock_store.update_event_count.call_args[1]["source_type"] == "azure_nsg_flow"

    def test_no_cosmos_endpoint(self):
        collector_module.COSMOS_ENDPOINT = ""
        collector_module.COSMOS_HEALTH_CONTAINER = ""
        collector_module._report_health(100)  # No crash


# ===========================================================================
# Test: _parse_blob_url
# ===========================================================================

class TestParseBlobUrl:
    """Tests for blob URL parsing."""

    def test_standard_url(self):
        url = "https://account.blob.core.windows.net/nsg-logs/path/to/file.json"
        container, blob = collector_module._parse_blob_url(url)
        assert container == "nsg-logs"
        assert blob == "path/to/file.json"

    def test_empty_url(self):
        container, blob = collector_module._parse_blob_url("")
        assert container == ""
        assert blob == ""

    def test_no_blob_path(self):
        container, blob = collector_module._parse_blob_url("https://account.blob.core.windows.net/container")
        assert container == ""
        assert blob == ""


# ===========================================================================
# Test: blob_trigger
# ===========================================================================

class TestBlobTrigger:
    """Tests for the blob trigger entry point."""

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_file(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        content = json.dumps(_SAMPLE_NSG_FILE).encode("utf-8")
        result = collector_module.blob_trigger(content, _SAMPLE_BLOB_PATH)

        assert result["status"] == "success"
        assert result["mode"] == "blob_trigger"
        assert result["total_events"] >= 3
        assert result["nsg_name"] == "NSG1"
        mock_health.assert_called_once()

    @patch.object(collector_module, "_report_health")
    def test_empty_file(self, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        content = json.dumps({"records": []}).encode("utf-8")
        result = collector_module.blob_trigger(content, _SAMPLE_BLOB_PATH)
        assert result["total_events"] == 0
        mock_health.assert_not_called()

    def test_missing_connection_string(self):
        collector_module.STORAGE_CONNECTION_STRING = ""
        content = json.dumps(_SAMPLE_NSG_FILE).encode("utf-8")
        result = collector_module.blob_trigger(content, _SAMPLE_BLOB_PATH)
        assert result["status"] == "error"


# ===========================================================================
# Test: event_grid_trigger
# ===========================================================================

class TestEventGridTrigger:
    """Tests for the Event Grid trigger entry point."""

    @patch("azure_nsg_flow_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_event(self, mock_batch, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_blob_client = MagicMock()
        mock_service.get_blob_client.return_value = mock_blob_client
        mock_download = MagicMock()
        mock_blob_client.download_blob.return_value = mock_download
        mock_download.readall.return_value = json.dumps(_SAMPLE_NSG_FILE).encode("utf-8")

        event = {
            "data": {
                "url": f"https://account.blob.core.windows.net/nsg-logs/{_SAMPLE_BLOB_PATH}",
                "contentLength": 1024,
            }
        }

        result = collector_module.event_grid_trigger(event)
        assert result["status"] == "success"
        assert result["total_events"] >= 3
        mock_health.assert_called_once()

    def test_missing_blob_url(self):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        result = collector_module.event_grid_trigger({"data": {}})
        assert result["status"] == "error"
        assert result["error"] == "no_blob_url"

    def test_missing_connection_string(self):
        collector_module.STORAGE_CONNECTION_STRING = ""
        result = collector_module.event_grid_trigger({"data": {"url": "https://a.b/c/d"}})
        assert result["status"] == "error"


# ===========================================================================
# Test: http_trigger
# ===========================================================================

class TestHttpTrigger:
    """Tests for the HTTP trigger entry point."""

    @patch("azure_nsg_flow_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_request(self, mock_batch, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_blob_client = MagicMock()
        mock_service.get_blob_client.return_value = mock_blob_client
        mock_download = MagicMock()
        mock_blob_client.download_blob.return_value = mock_download
        mock_download.readall.return_value = json.dumps(_SAMPLE_NSG_FILE).encode("utf-8")

        result = collector_module.http_trigger({
            "container": "nsg-logs",
            "blob_name": _SAMPLE_BLOB_PATH,
        })
        assert result["status"] == "success"
        assert result["total_events"] >= 3

    def test_missing_params(self):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        result = collector_module.http_trigger({})
        assert result["status"] == "error"
        assert result["error"] == "missing_container_or_blob"

    def test_missing_connection_string(self):
        collector_module.STORAGE_CONNECTION_STRING = ""
        result = collector_module.http_trigger({"container": "c", "blob_name": "b"})
        assert result["status"] == "error"


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests."""

    @patch("azure_nsg_flow_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    def test_full_pipeline(self, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        collector_module.OUTPUT_CONTAINER = "mantissa-logs"

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        content = json.dumps(_SAMPLE_NSG_FILE).encode("utf-8")
        result = collector_module.blob_trigger(content, _SAMPLE_BLOB_PATH)

        assert result["status"] == "success"
        assert result["total_events"] >= 3
        mock_blob.upload_blob.assert_called_once()

        # Verify NDJSON content
        call_args = mock_blob.upload_blob.call_args
        body = call_args[0][0]
        lines = body.strip().split("\n")
        assert len(lines) >= 3
        for line in lines:
            parsed = json.loads(line)
            assert "network" in parsed["metadata"]["tags"]

    @patch("azure_nsg_flow_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        content = json.dumps(_SAMPLE_NSG_FILE).encode("utf-8")
        result = collector_module.blob_trigger(content, _SAMPLE_BLOB_PATH)

        blob_path = mock_container.get_blob_client.call_args[0][0]
        assert blob_path.startswith("azure_nsg_flow/raw/")
        parts = blob_path.split("/")
        assert parts[0] == "azure_nsg_flow"
        assert parts[1] == "raw"
