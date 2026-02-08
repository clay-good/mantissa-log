"""Unit tests for the GCP Cloud DNS Log Collector Cloud Function."""

import base64
import json
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Ensure the GCP functions directory is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/gcp/functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/shared"))

import gcp_dns_collector as collector_module


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_SAMPLE_DNS_ENTRY = {
    "logName": "projects/my-project/logs/dns.googleapis.com%2Fdns_queries",
    "resource": {
        "type": "dns_query",
        "labels": {
            "project_id": "my-project",
            "target_type": "public-zone",
            "target_name": "example-zone",
            "source_type": "inbound-forwarding",
        },
    },
    "jsonPayload": {
        "queryName": "api.example.com.",
        "queryType": "A",
        "responseCode": "NOERROR",
        "protocol": "UDP",
        "sourceIP": "10.0.0.4",
        "vmInstanceId": "1234567890",
        "vmInstanceName": "web-server-1",
        "vmProjectId": "my-project",
        "vmZoneName": "us-east1-b",
        "answers": [
            {"name": "api.example.com.", "type": "A", "rdata": "93.184.216.34"}
        ],
        "serverLatency": "0.001s",
        "sourceNetwork": "projects/my-project/global/networks/default",
    },
    "timestamp": "2025-06-15T10:00:00Z",
}

_SAMPLE_DNS_ENTRY_NXDOMAIN = {
    "logName": "projects/my-project/logs/dns.googleapis.com%2Fdns_queries",
    "resource": {
        "type": "dns_query",
        "labels": {"project_id": "my-project"},
    },
    "jsonPayload": {
        "queryName": "nonexistent.example.com.",
        "queryType": "A",
        "responseCode": "NXDOMAIN",
        "protocol": "UDP",
        "sourceIP": "10.0.0.5",
    },
    "timestamp": "2025-06-15T10:00:01Z",
}

_SAMPLE_DNS_ENTRY_AAAA = {
    "logName": "projects/my-project/logs/dns.googleapis.com%2Fdns_queries",
    "resource": {
        "type": "dns_query",
        "labels": {"project_id": "my-project"},
    },
    "jsonPayload": {
        "queryName": "ipv6.example.com.",
        "queryType": "AAAA",
        "responseCode": "NOERROR",
        "protocol": "UDP",
        "sourceIP": "10.0.0.6",
        "answers": [
            {"name": "ipv6.example.com.", "type": "AAAA", "rdata": "2001:db8::1"}
        ],
    },
    "timestamp": "2025-06-15T10:00:02Z",
}


def _make_cloud_event(entries):
    """Create a simulated CloudEvent with base64-encoded Pub/Sub data."""
    encoded = base64.b64encode(json.dumps(entries).encode("utf-8")).decode("utf-8")
    return SimpleNamespace(data={"message": {"data": encoded}})


# ===========================================================================
# Test: _decode_pubsub_batch
# ===========================================================================

class TestDecodePubSubBatch:
    """Tests for Pub/Sub message decoding."""

    def test_single_entry(self):
        event = _make_cloud_event(_SAMPLE_DNS_ENTRY)
        result = collector_module._decode_pubsub_batch(event)
        assert len(result) == 1

    def test_batch_entries(self):
        event = _make_cloud_event([_SAMPLE_DNS_ENTRY, _SAMPLE_DNS_ENTRY_NXDOMAIN])
        result = collector_module._decode_pubsub_batch(event)
        assert len(result) == 2

    def test_empty_data(self):
        event = SimpleNamespace(data={"message": {"data": ""}})
        result = collector_module._decode_pubsub_batch(event)
        assert result == []

    def test_non_dict_entries_filtered(self):
        event = _make_cloud_event([_SAMPLE_DNS_ENTRY, "not a dict", 42])
        result = collector_module._decode_pubsub_batch(event)
        assert len(result) == 1


# ===========================================================================
# Test: _decode_http_request
# ===========================================================================

class TestDecodeHttpRequest:
    """Tests for HTTP request decoding."""

    def test_pubsub_push_format(self):
        encoded = base64.b64encode(
            json.dumps(_SAMPLE_DNS_ENTRY).encode("utf-8")
        ).decode("utf-8")
        result = collector_module._decode_http_request({"message": {"data": encoded}})
        assert len(result) == 1

    def test_direct_entries(self):
        result = collector_module._decode_http_request(
            {"entries": [_SAMPLE_DNS_ENTRY, _SAMPLE_DNS_ENTRY_NXDOMAIN]}
        )
        assert len(result) == 2

    def test_single_entry_body(self):
        result = collector_module._decode_http_request(_SAMPLE_DNS_ENTRY)
        assert len(result) == 1

    def test_empty_request(self):
        result = collector_module._decode_http_request({})
        assert result == []


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
        event = result[0]
        assert event["metadata"]["is_nxdomain"] is True

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
            {"not": "a dns log"},
        ])
        assert len(result) >= 1

    def test_empty_input(self):
        assert collector_module._parse_dns_events([]) == []

    def test_parsed_event_structure(self):
        result = collector_module._parse_dns_events([_SAMPLE_DNS_ENTRY])
        event = result[0]
        for key in ("timestamp", "source_ip", "action", "result", "service", "metadata", "raw_event"):
            assert key in event

    def test_subdomain_analysis(self):
        result = collector_module._parse_dns_events([_SAMPLE_DNS_ENTRY])
        meta = result[0]["metadata"]
        assert meta["subdomain_count"] == 3  # api, example, com
        assert isinstance(meta["subdomain_entropy"], float)


# ===========================================================================
# Test: _write_to_gcs
# ===========================================================================

class TestWriteToGCS:
    """Tests for GCS writes."""

    @patch("gcp_dns_collector._gcs_storage")
    def test_writes_ndjson(self, mock_storage):
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        events = collector_module._parse_dns_events([_SAMPLE_DNS_ENTRY])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

        path = collector_module._write_to_gcs(events, "my-bucket", ts, "part01")
        assert path == "gcp_cloud_dns/raw/2025/06/15/10/dns_part01.json"
        mock_blob.upload_from_string.assert_called_once()

    @patch("gcp_dns_collector._gcs_storage")
    def test_empty_events_returns_none(self, mock_storage):
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert collector_module._write_to_gcs([], "my-bucket", ts) is None

    @patch("gcp_dns_collector._gcs_storage")
    def test_gcs_failure_returns_none(self, mock_storage):
        mock_storage.Client.side_effect = Exception("GCS error")
        events = collector_module._parse_dns_events([_SAMPLE_DNS_ENTRY])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert collector_module._write_to_gcs(events, "my-bucket", ts) is None


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting and writing."""

    @patch.object(collector_module, "_write_to_gcs")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "path1"
        paths = collector_module._batch_and_write([{"a": 1}], "bucket", 10)
        assert paths == ["path1"]

    @patch.object(collector_module, "_write_to_gcs")
    def test_multiple_batches(self, mock_write):
        mock_write.side_effect = ["p1", "p2", "p3"]
        events = [{"a": i} for i in range(25)]
        paths = collector_module._batch_and_write(events, "bucket", 10)
        assert len(paths) == 3


# ===========================================================================
# Test: _report_health
# ===========================================================================

class TestReportHealth:
    """Tests for health reporting."""

    @patch("src.shared.health.health_state_store.FirestoreHealthStateStore")
    def test_reports_health(self, mock_store_cls):
        collector_module.HEALTH_STATE_COLLECTION = "health"
        collector_module.TENANT_ID = "t1"
        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        collector_module._report_health(50)
        mock_store.update_event_count.assert_called_once()
        assert mock_store.update_event_count.call_args[1]["source_type"] == "gcp_cloud_dns"

    def test_no_health_collection(self):
        collector_module.HEALTH_STATE_COLLECTION = ""
        collector_module._report_health(100)  # No crash


# ===========================================================================
# Test: dns_pubsub entry point
# ===========================================================================

class TestDnsPubSub:
    """Tests for the Pub/Sub Cloud Function entry point."""

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_entry(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        event = _make_cloud_event(_SAMPLE_DNS_ENTRY)
        result = collector_module.dns_pubsub(event)

        assert result["status"] == "success"
        assert result["total_events"] == 1
        mock_health.assert_called_once_with(1)

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_batch(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        event = _make_cloud_event([_SAMPLE_DNS_ENTRY, _SAMPLE_DNS_ENTRY_NXDOMAIN, _SAMPLE_DNS_ENTRY_AAAA])
        result = collector_module.dns_pubsub(event)

        assert result["total_events"] == 3

    @patch.object(collector_module, "_report_health")
    def test_empty_message(self, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        event = SimpleNamespace(data={"message": {"data": ""}})
        result = collector_module.dns_pubsub(event)
        assert result["total_events"] == 0
        mock_health.assert_not_called()

    def test_missing_gcs_bucket(self):
        collector_module.GCS_BUCKET = None
        event = _make_cloud_event(_SAMPLE_DNS_ENTRY)
        result = collector_module.dns_pubsub(event)
        assert result["status"] == "error"


# ===========================================================================
# Test: dns_http entry point
# ===========================================================================

class TestDnsHttp:
    """Tests for the HTTP Cloud Function entry point."""

    def _make_request(self, json_body):
        mock_request = MagicMock()
        mock_request.get_json.return_value = json_body
        return mock_request

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_pubsub_push(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        encoded = base64.b64encode(json.dumps(_SAMPLE_DNS_ENTRY).encode("utf-8")).decode("utf-8")
        request = self._make_request({"message": {"data": encoded}})
        result = collector_module.dns_http(request)
        assert result["status"] == "success"

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_direct_entries(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        request = self._make_request({"entries": [_SAMPLE_DNS_ENTRY]})
        result = collector_module.dns_http(request)
        assert result["status"] == "success"

    def test_empty_request(self):
        collector_module.GCS_BUCKET = "test-lake"
        request = self._make_request(None)
        result = collector_module.dns_http(request)
        if isinstance(result, tuple):
            assert result[1] == 400

    def test_missing_gcs_bucket(self):
        collector_module.GCS_BUCKET = None
        request = self._make_request({"entries": [_SAMPLE_DNS_ENTRY]})
        result = collector_module.dns_http(request)
        if isinstance(result, tuple):
            assert result[1] == 500


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests."""

    @patch("gcp_dns_collector._gcs_storage")
    @patch.object(collector_module, "_report_health")
    def test_pubsub_full_pipeline(self, mock_health, mock_storage):
        collector_module.GCS_BUCKET = "test-lake"
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        event = _make_cloud_event([_SAMPLE_DNS_ENTRY, _SAMPLE_DNS_ENTRY_NXDOMAIN])
        result = collector_module.dns_pubsub(event)

        assert result["total_events"] == 2
        assert result["files_written"] == 1
        mock_blob.upload_from_string.assert_called_once()

        content = mock_blob.upload_from_string.call_args[0][0]
        lines = content.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "dns" in parsed["metadata"]["tags"]

    @patch("gcp_dns_collector._gcs_storage")
    @patch.object(collector_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_storage):
        collector_module.GCS_BUCKET = "test-lake"
        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        event = _make_cloud_event(_SAMPLE_DNS_ENTRY)
        collector_module.dns_pubsub(event)

        blob_path = mock_bucket.blob.call_args[0][0]
        assert blob_path.startswith("gcp_cloud_dns/raw/")
        parts = blob_path.split("/")
        assert parts[0] == "gcp_cloud_dns"
        assert parts[1] == "raw"
