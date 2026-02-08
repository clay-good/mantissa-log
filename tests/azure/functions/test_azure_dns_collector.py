"""Unit tests for the Azure DNS Analytics Log Collector."""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# Ensure the Azure functions directory is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/azure/functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/shared"))

import azure_dns_collector as collector_module


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_SAMPLE_DNS_ENTRY = {
    "category": "DnsQueryLog",
    "operationName": "DnsQueryLog",
    "properties": {
        "QueryName": "api.example.com.",
        "QueryType": "A",
        "RCODE": "NOERROR",
        "ClientIP": "10.0.0.4",
        "Server": "dns-resolver-1",
        "TimeTaken": 1500,
        "Answer": "93.184.216.34",
        "ClientSubnet": "10.0.0.0/24",
    },
    "resourceId": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/dnszones/example.com",
    "time": "2025-06-15T10:00:00.0000000Z",
}

_SAMPLE_DNS_ENTRY_NXDOMAIN = {
    "category": "DnsQueryLog",
    "operationName": "DnsQueryLog",
    "properties": {
        "QueryName": "nonexistent.example.com.",
        "QueryType": "A",
        "RCODE": "NXDOMAIN",
        "ClientIP": "10.0.0.5",
        "TimeTaken": 500,
    },
    "resourceId": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/dnszones/example.com",
    "time": "2025-06-15T10:00:01.0000000Z",
}

_SAMPLE_DNS_ENTRY_AAAA = {
    "category": "DnsQueryLog",
    "operationName": "DnsQueryLog",
    "properties": {
        "QueryName": "ipv6.example.com.",
        "QueryType": "AAAA",
        "RCODE": "NOERROR",
        "ClientIP": "10.0.0.6",
        "Answer": "2001:db8::1",
    },
    "resourceId": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/dnszones/example.com",
    "time": "2025-06-15T10:00:02.0000000Z",
}


# ===========================================================================
# Test: _decode_event_hub_messages
# ===========================================================================

class TestDecodeEventHubMessages:
    """Tests for Event Hub message decoding."""

    def test_decode_bytes_messages(self):
        messages = [json.dumps(_SAMPLE_DNS_ENTRY).encode("utf-8")]
        result = collector_module._decode_event_hub_messages(messages)
        assert len(result) == 1

    def test_decode_string_messages(self):
        messages = [json.dumps(_SAMPLE_DNS_ENTRY)]
        result = collector_module._decode_event_hub_messages(messages)
        assert len(result) == 1

    def test_decode_dict_messages(self):
        result = collector_module._decode_event_hub_messages([_SAMPLE_DNS_ENTRY])
        assert len(result) == 1

    def test_decode_records_wrapper(self):
        """Azure Monitor wraps entries in records array."""
        wrapper = {"records": [_SAMPLE_DNS_ENTRY, _SAMPLE_DNS_ENTRY_NXDOMAIN]}
        result = collector_module._decode_event_hub_messages([json.dumps(wrapper).encode("utf-8")])
        assert len(result) == 2

    def test_decode_list_payload(self):
        payload = [_SAMPLE_DNS_ENTRY, _SAMPLE_DNS_ENTRY_NXDOMAIN]
        result = collector_module._decode_event_hub_messages([json.dumps(payload).encode("utf-8")])
        assert len(result) == 2

    def test_invalid_messages_skipped(self):
        messages = [
            json.dumps(_SAMPLE_DNS_ENTRY).encode("utf-8"),
            b"not json",
            b"",
        ]
        result = collector_module._decode_event_hub_messages(messages)
        assert len(result) == 1

    def test_empty_messages(self):
        assert collector_module._decode_event_hub_messages([]) == []

    def test_multiple_messages(self):
        messages = [
            json.dumps(_SAMPLE_DNS_ENTRY).encode("utf-8"),
            json.dumps(_SAMPLE_DNS_ENTRY_NXDOMAIN).encode("utf-8"),
        ]
        result = collector_module._decode_event_hub_messages(messages)
        assert len(result) == 2


# ===========================================================================
# Test: _decode_http_request
# ===========================================================================

class TestDecodeHttpRequest:
    """Tests for HTTP request decoding."""

    def test_records_array(self):
        result = collector_module._decode_http_request(
            {"records": [_SAMPLE_DNS_ENTRY, _SAMPLE_DNS_ENTRY_NXDOMAIN]}
        )
        assert len(result) == 2

    def test_entries_array(self):
        result = collector_module._decode_http_request(
            {"entries": [_SAMPLE_DNS_ENTRY]}
        )
        assert len(result) == 1

    def test_single_entry_body(self):
        result = collector_module._decode_http_request(_SAMPLE_DNS_ENTRY)
        assert len(result) == 1

    def test_empty_request(self):
        assert collector_module._decode_http_request({}) == []


# ===========================================================================
# Test: _parse_dns_events
# ===========================================================================

class TestParseDNSEvents:
    """Tests for DNS event parsing."""

    def test_parse_valid_event(self):
        result = collector_module._parse_dns_events([_SAMPLE_DNS_ENTRY])
        assert len(result) == 1
        event = result[0]
        assert event["source_ip"] == "10.0.0.4"
        assert "dns" in event["metadata"]["tags"]

    def test_parse_nxdomain(self):
        result = collector_module._parse_dns_events([_SAMPLE_DNS_ENTRY_NXDOMAIN])
        assert len(result) == 1
        assert result[0]["metadata"]["is_nxdomain"] is True

    def test_parse_multiple(self):
        result = collector_module._parse_dns_events([
            _SAMPLE_DNS_ENTRY,
            _SAMPLE_DNS_ENTRY_NXDOMAIN,
            _SAMPLE_DNS_ENTRY_AAAA,
        ])
        assert len(result) == 3

    def test_invalid_events_skipped(self):
        result = collector_module._parse_dns_events([
            _SAMPLE_DNS_ENTRY,
            {"not": "dns data"},
        ])
        assert len(result) >= 1

    def test_empty_input(self):
        assert collector_module._parse_dns_events([]) == []

    def test_parsed_event_structure(self):
        result = collector_module._parse_dns_events([_SAMPLE_DNS_ENTRY])
        event = result[0]
        for key in ("timestamp", "source_ip", "action", "result", "service", "metadata", "raw_event"):
            assert key in event


# ===========================================================================
# Test: _write_to_blob
# ===========================================================================

class TestWriteToBlob:
    """Tests for Blob Storage writes."""

    @patch("azure_dns_collector.BlobServiceClient")
    def test_writes_ndjson(self, mock_blob_cls):
        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        events = collector_module._parse_dns_events([_SAMPLE_DNS_ENTRY])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

        path = collector_module._write_to_blob(events, "conn-str", "container", ts, "part01")
        assert path == "azure_dns/raw/2025/06/15/10/dns_part01.json"
        mock_blob.upload_blob.assert_called_once()

    @patch("azure_dns_collector.BlobServiceClient")
    def test_empty_events_returns_none(self, mock_blob_cls):
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert collector_module._write_to_blob([], "conn-str", "container", ts) is None

    @patch("azure_dns_collector.BlobServiceClient")
    def test_blob_failure_returns_none(self, mock_blob_cls):
        mock_blob_cls.from_connection_string.side_effect = Exception("Blob error")
        events = collector_module._parse_dns_events([_SAMPLE_DNS_ENTRY])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert collector_module._write_to_blob(events, "conn-str", "container", ts) is None


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting."""

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
        assert mock_store.update_event_count.call_args[1]["source_type"] == "azure_dns"

    def test_no_cosmos_endpoint(self):
        collector_module.COSMOS_ENDPOINT = ""
        collector_module.COSMOS_HEALTH_CONTAINER = ""
        collector_module._report_health(100)  # No crash


# ===========================================================================
# Test: event_hub_trigger
# ===========================================================================

class TestEventHubTrigger:
    """Tests for the Event Hub trigger entry point."""

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_messages(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        messages = [
            json.dumps(_SAMPLE_DNS_ENTRY).encode("utf-8"),
            json.dumps(_SAMPLE_DNS_ENTRY_NXDOMAIN).encode("utf-8"),
        ]
        result = collector_module.event_hub_trigger(messages)

        assert result["status"] == "success"
        assert result["mode"] == "event_hub"
        assert result["total_events"] == 2
        mock_health.assert_called_once_with(2)

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_records_wrapper(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        wrapper = {"records": [_SAMPLE_DNS_ENTRY, _SAMPLE_DNS_ENTRY_AAAA]}
        messages = [json.dumps(wrapper).encode("utf-8")]
        result = collector_module.event_hub_trigger(messages)

        assert result["total_events"] == 2

    @patch.object(collector_module, "_report_health")
    def test_empty_messages(self, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        result = collector_module.event_hub_trigger([])
        assert result["total_events"] == 0
        mock_health.assert_not_called()

    def test_missing_connection_string(self):
        collector_module.STORAGE_CONNECTION_STRING = ""
        result = collector_module.event_hub_trigger([json.dumps(_SAMPLE_DNS_ENTRY).encode("utf-8")])
        assert result["status"] == "error"


# ===========================================================================
# Test: http_trigger
# ===========================================================================

class TestHttpTrigger:
    """Tests for the HTTP trigger entry point."""

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_records_format(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        result = collector_module.http_trigger(
            {"records": [_SAMPLE_DNS_ENTRY, _SAMPLE_DNS_ENTRY_NXDOMAIN]}
        )
        assert result["status"] == "success"
        assert result["total_events"] == 2

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_single_entry(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        result = collector_module.http_trigger(_SAMPLE_DNS_ENTRY)
        assert result["total_events"] == 1

    def test_empty_body(self):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        result = collector_module.http_trigger({})
        assert result["total_events"] == 0

    def test_missing_connection_string(self):
        collector_module.STORAGE_CONNECTION_STRING = ""
        result = collector_module.http_trigger({"records": [_SAMPLE_DNS_ENTRY]})
        assert result["status"] == "error"


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests."""

    @patch("azure_dns_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    def test_event_hub_full_pipeline(self, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        collector_module.OUTPUT_CONTAINER = "mantissa-logs"

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        messages = [
            json.dumps(_SAMPLE_DNS_ENTRY).encode("utf-8"),
            json.dumps(_SAMPLE_DNS_ENTRY_NXDOMAIN).encode("utf-8"),
            json.dumps(_SAMPLE_DNS_ENTRY_AAAA).encode("utf-8"),
        ]
        result = collector_module.event_hub_trigger(messages)

        assert result["total_events"] == 3
        assert result["files_written"] == 1
        mock_blob.upload_blob.assert_called_once()

        content = mock_blob.upload_blob.call_args[0][0]
        lines = content.strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "dns" in parsed["metadata"]["tags"]

    @patch("azure_dns_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        messages = [json.dumps(_SAMPLE_DNS_ENTRY).encode("utf-8")]
        collector_module.event_hub_trigger(messages)

        blob_path = mock_container.get_blob_client.call_args[0][0]
        assert blob_path.startswith("azure_dns/raw/")
        parts = blob_path.split("/")
        assert parts[0] == "azure_dns"
        assert parts[1] == "raw"
