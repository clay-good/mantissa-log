"""Unit tests for the Azure Firewall Log Collector."""

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

import azure_firewall_collector as collector_module


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_SAMPLE_AZ_FW_ALLOW = {
    "category": "AzureFirewallNetworkRule",
    "operationName": "AzureFirewallNetworkRuleLog",
    "properties": {
        "SourceIP": "10.0.0.4",
        "SourcePort": "54321",
        "DestinationIP": "93.184.216.34",
        "DestinationPort": "443",
        "Protocol": "TCP",
        "Action": "Allow",
        "RuleCollection": "AllowWeb",
        "Rule": "AllowHTTPS",
    },
    "resourceId": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/azureFirewalls/fw1",
    "time": "2025-06-15T10:00:00.0000000Z",
}

_SAMPLE_AZ_FW_DENY = {
    "category": "AzureFirewallNetworkRule",
    "operationName": "AzureFirewallNetworkRuleLog",
    "properties": {
        "SourceIP": "203.0.113.50",
        "SourcePort": "12345",
        "DestinationIP": "10.0.0.10",
        "DestinationPort": "22",
        "Protocol": "TCP",
        "Action": "Deny",
        "RuleCollection": "DenySSH",
        "Rule": "BlockSSHExternal",
    },
    "resourceId": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/azureFirewalls/fw1",
    "time": "2025-06-15T10:00:01.0000000Z",
}

_SAMPLE_AZ_FW_THREAT = {
    "category": "AzureFirewallThreatIntel",
    "operationName": "AzureFirewallThreatIntelLog",
    "properties": {
        "SourceIP": "10.0.0.100",
        "DestinationIP": "198.51.100.1",
        "DestinationPort": "80",
        "Protocol": "TCP",
        "Action": "Deny",
        "ThreatIntelligence": "Malware C2 Server",
        "msg": "TCP request from 10.0.0.100:45678 to 198.51.100.1:80. Action: Deny.",
    },
    "resourceId": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/azureFirewalls/fw1",
    "time": "2025-06-15T10:00:02.0000000Z",
}


# ===========================================================================
# Test: _decode_event_hub_messages
# ===========================================================================

class TestDecodeEventHubMessages:
    """Tests for Event Hub message decoding."""

    def test_decode_bytes_messages(self):
        messages = [json.dumps(_SAMPLE_AZ_FW_ALLOW).encode("utf-8")]
        result = collector_module._decode_event_hub_messages(messages)
        assert len(result) == 1

    def test_decode_string_messages(self):
        messages = [json.dumps(_SAMPLE_AZ_FW_ALLOW)]
        result = collector_module._decode_event_hub_messages(messages)
        assert len(result) == 1

    def test_decode_dict_messages(self):
        result = collector_module._decode_event_hub_messages(
            [_SAMPLE_AZ_FW_ALLOW]
        )
        assert len(result) == 1

    def test_decode_records_wrapper(self):
        wrapper = {
            "records": [_SAMPLE_AZ_FW_ALLOW, _SAMPLE_AZ_FW_DENY]
        }
        result = collector_module._decode_event_hub_messages(
            [json.dumps(wrapper).encode("utf-8")]
        )
        assert len(result) == 2

    def test_decode_list_payload(self):
        payload = [_SAMPLE_AZ_FW_ALLOW, _SAMPLE_AZ_FW_DENY]
        result = collector_module._decode_event_hub_messages(
            [json.dumps(payload).encode("utf-8")]
        )
        assert len(result) == 2

    def test_invalid_messages_skipped(self):
        messages = [
            json.dumps(_SAMPLE_AZ_FW_ALLOW).encode("utf-8"),
            b"not json",
            b"",
        ]
        result = collector_module._decode_event_hub_messages(messages)
        assert len(result) == 1

    def test_empty_messages(self):
        assert collector_module._decode_event_hub_messages([]) == []

    def test_multiple_messages(self):
        messages = [
            json.dumps(_SAMPLE_AZ_FW_ALLOW).encode("utf-8"),
            json.dumps(_SAMPLE_AZ_FW_DENY).encode("utf-8"),
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
            {"records": [_SAMPLE_AZ_FW_ALLOW, _SAMPLE_AZ_FW_DENY]}
        )
        assert len(result) == 2

    def test_entries_array(self):
        result = collector_module._decode_http_request(
            {"entries": [_SAMPLE_AZ_FW_ALLOW]}
        )
        assert len(result) == 1

    def test_single_entry_body(self):
        result = collector_module._decode_http_request(_SAMPLE_AZ_FW_ALLOW)
        assert len(result) == 1

    def test_empty_request(self):
        assert collector_module._decode_http_request({}) == []


# ===========================================================================
# Test: _parse_firewall_events
# ===========================================================================

class TestParseFirewallEvents:
    """Tests for firewall event parsing."""

    def test_parse_allow(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_AZ_FW_ALLOW]
        )
        assert len(result) == 1
        event = result[0]
        assert "firewall" in event["metadata"]["tags"]

    def test_parse_deny(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_AZ_FW_DENY]
        )
        assert len(result) == 1

    def test_parse_threat(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_AZ_FW_THREAT]
        )
        assert len(result) == 1

    def test_parse_multiple(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_AZ_FW_ALLOW, _SAMPLE_AZ_FW_DENY, _SAMPLE_AZ_FW_THREAT]
        )
        assert len(result) == 3

    def test_invalid_events_skipped(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_AZ_FW_ALLOW, {"not": "firewall data"}]
        )
        assert len(result) >= 1

    def test_empty_input(self):
        assert collector_module._parse_firewall_events([]) == []

    def test_parsed_event_structure(self):
        result = collector_module._parse_firewall_events(
            [_SAMPLE_AZ_FW_ALLOW]
        )
        event = result[0]
        for key in (
            "timestamp",
            "action",
            "result",
            "service",
            "metadata",
            "raw_event",
        ):
            assert key in event


# ===========================================================================
# Test: _write_to_blob
# ===========================================================================

class TestWriteToBlob:
    """Tests for Blob Storage writes."""

    @patch("azure_firewall_collector.BlobServiceClient")
    def test_writes_ndjson(self, mock_blob_cls):
        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        events = collector_module._parse_firewall_events(
            [_SAMPLE_AZ_FW_ALLOW]
        )
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

        path = collector_module._write_to_blob(
            events, "conn-str", "container", ts, "part01"
        )
        assert path == "azure_firewall/raw/2025/06/15/10/fw_part01.json"
        mock_blob.upload_blob.assert_called_once()

    @patch("azure_firewall_collector.BlobServiceClient")
    def test_empty_events_returns_none(self, mock_blob_cls):
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert (
            collector_module._write_to_blob([], "conn-str", "container", ts)
            is None
        )

    @patch("azure_firewall_collector.BlobServiceClient")
    def test_blob_failure_returns_none(self, mock_blob_cls):
        mock_blob_cls.from_connection_string.side_effect = Exception(
            "Blob error"
        )
        events = collector_module._parse_firewall_events(
            [_SAMPLE_AZ_FW_ALLOW]
        )
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert (
            collector_module._write_to_blob(events, "conn", "cont", ts) is None
        )


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting."""

    @patch.object(collector_module, "_write_to_blob")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "path1"
        paths = collector_module._batch_and_write(
            [{"a": 1}], "conn", "cont", 10
        )
        assert paths == ["path1"]

    @patch.object(collector_module, "_write_to_blob")
    def test_multiple_batches(self, mock_write):
        mock_write.side_effect = ["p1", "p2", "p3"]
        events = [{"a": i} for i in range(25)]
        paths = collector_module._batch_and_write(
            events, "conn", "cont", 10
        )
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
        assert (
            mock_store.update_event_count.call_args[1]["source_type"]
            == "azure_firewall"
        )

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
            json.dumps(_SAMPLE_AZ_FW_ALLOW).encode("utf-8"),
            json.dumps(_SAMPLE_AZ_FW_DENY).encode("utf-8"),
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

        wrapper = {
            "records": [_SAMPLE_AZ_FW_ALLOW, _SAMPLE_AZ_FW_THREAT]
        }
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
        result = collector_module.event_hub_trigger(
            [json.dumps(_SAMPLE_AZ_FW_ALLOW).encode("utf-8")]
        )
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
            {"records": [_SAMPLE_AZ_FW_ALLOW, _SAMPLE_AZ_FW_DENY]}
        )
        assert result["status"] == "success"
        assert result["total_events"] == 2

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_single_entry(self, mock_batch, mock_health):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        mock_batch.return_value = ["path1"]

        result = collector_module.http_trigger(_SAMPLE_AZ_FW_ALLOW)
        assert result["total_events"] == 1

    def test_empty_body(self):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"
        result = collector_module.http_trigger({})
        assert result["total_events"] == 0

    def test_missing_connection_string(self):
        collector_module.STORAGE_CONNECTION_STRING = ""
        result = collector_module.http_trigger(
            {"records": [_SAMPLE_AZ_FW_ALLOW]}
        )
        assert result["status"] == "error"


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests."""

    @patch("azure_firewall_collector.BlobServiceClient")
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
            json.dumps(_SAMPLE_AZ_FW_ALLOW).encode("utf-8"),
            json.dumps(_SAMPLE_AZ_FW_DENY).encode("utf-8"),
            json.dumps(_SAMPLE_AZ_FW_THREAT).encode("utf-8"),
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
            assert "firewall" in parsed["metadata"]["tags"]

    @patch("azure_firewall_collector.BlobServiceClient")
    @patch.object(collector_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_blob_cls):
        collector_module.STORAGE_CONNECTION_STRING = "conn-str"

        mock_service = MagicMock()
        mock_blob_cls.from_connection_string.return_value = mock_service
        mock_container = MagicMock()
        mock_service.get_container_client.return_value = mock_container
        mock_blob = MagicMock()
        mock_container.get_blob_client.return_value = mock_blob

        messages = [json.dumps(_SAMPLE_AZ_FW_ALLOW).encode("utf-8")]
        collector_module.event_hub_trigger(messages)

        blob_path = mock_container.get_blob_client.call_args[0][0]
        assert blob_path.startswith("azure_firewall/raw/")
        parts = blob_path.split("/")
        assert parts[0] == "azure_firewall"
        assert parts[1] == "raw"
