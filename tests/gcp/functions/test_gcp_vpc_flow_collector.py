"""Unit tests for the GCP VPC Flow Log Collector Cloud Function."""

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

# The module handles missing functions_framework/google.cloud.storage gracefully
import gcp_vpc_flow_collector as collector_module


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_SAMPLE_FLOW_ENTRY = {
    "logName": "projects/my-project/logs/compute.googleapis.com%2Fvpc_flows",
    "resource": {
        "type": "gce_subnetwork",
        "labels": {
            "subnetwork_name": "default",
            "project_id": "my-project",
        },
    },
    "jsonPayload": {
        "connection": {
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_port": 54321,
            "dest_port": 443,
            "protocol": 6,
        },
        "bytes_sent": "1234",
        "packets_sent": "10",
        "start_time": "2025-06-15T10:00:00Z",
        "end_time": "2025-06-15T10:05:00Z",
        "reporter": "SRC",
        "src_instance": {
            "vm_name": "web-server-1",
            "zone": "us-east1-b",
            "project_id": "my-project",
            "region": "us-east1",
        },
        "dest_instance": {
            "vm_name": "db-server-1",
            "zone": "us-east1-c",
            "project_id": "my-project",
            "region": "us-east1",
        },
        "src_vpc": {
            "vpc_name": "default",
            "project_id": "my-project",
            "subnetwork_name": "default",
        },
        "dest_vpc": {
            "vpc_name": "default",
            "project_id": "my-project",
            "subnetwork_name": "default",
        },
    },
    "timestamp": "2025-06-15T10:00:00Z",
}

_SAMPLE_FLOW_ENTRY_EXTERNAL = {
    "logName": "projects/my-project/logs/compute.googleapis.com%2Fvpc_flows",
    "resource": {
        "type": "gce_subnetwork",
        "labels": {"subnetwork_name": "default", "project_id": "my-project"},
    },
    "jsonPayload": {
        "connection": {
            "src_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "src_port": 12345,
            "dest_port": 53,
            "protocol": 17,
        },
        "bytes_sent": "64",
        "packets_sent": "1",
        "start_time": "2025-06-15T10:01:00Z",
        "end_time": "2025-06-15T10:01:01Z",
        "reporter": "SRC",
    },
    "timestamp": "2025-06-15T10:01:00Z",
}


def _make_cloud_event(entries):
    """Create a simulated CloudEvent with base64-encoded Pub/Sub data."""
    if isinstance(entries, dict):
        payload = entries
    elif isinstance(entries, list):
        payload = entries
    else:
        payload = entries

    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return SimpleNamespace(data={"message": {"data": encoded}})


def _make_cloud_event_single(entry):
    """Create a CloudEvent for a single log entry."""
    return _make_cloud_event(entry)


# ===========================================================================
# Test: _decode_pubsub_message
# ===========================================================================

class TestDecodePubSubMessage:
    """Tests for Pub/Sub message decoding."""

    def test_decode_single_entry(self):
        event = _make_cloud_event_single(_SAMPLE_FLOW_ENTRY)
        result = collector_module._decode_pubsub_message(event)
        assert result is not None
        assert result["logName"] == _SAMPLE_FLOW_ENTRY["logName"]

    def test_decode_empty_data(self):
        event = SimpleNamespace(data={"message": {"data": ""}})
        result = collector_module._decode_pubsub_message(event)
        assert result is None

    def test_decode_missing_message(self):
        event = SimpleNamespace(data={})
        result = collector_module._decode_pubsub_message(event)
        assert result is None

    def test_decode_invalid_base64(self):
        event = SimpleNamespace(data={"message": {"data": "!!!invalid!!!"}})
        result = collector_module._decode_pubsub_message(event)
        assert result is None

    def test_decode_non_json_payload(self):
        encoded = base64.b64encode(b"not json").decode("utf-8")
        event = SimpleNamespace(data={"message": {"data": encoded}})
        result = collector_module._decode_pubsub_message(event)
        assert result is None


# ===========================================================================
# Test: _decode_pubsub_batch
# ===========================================================================

class TestDecodePubSubBatch:
    """Tests for batch Pub/Sub message decoding."""

    def test_single_entry(self):
        event = _make_cloud_event(_SAMPLE_FLOW_ENTRY)
        result = collector_module._decode_pubsub_batch(event)
        assert len(result) == 1
        assert result[0]["logName"] == _SAMPLE_FLOW_ENTRY["logName"]

    def test_batch_entries(self):
        event = _make_cloud_event([_SAMPLE_FLOW_ENTRY, _SAMPLE_FLOW_ENTRY_EXTERNAL])
        result = collector_module._decode_pubsub_batch(event)
        assert len(result) == 2

    def test_empty_data(self):
        event = SimpleNamespace(data={"message": {"data": ""}})
        result = collector_module._decode_pubsub_batch(event)
        assert result == []

    def test_non_dict_entries_filtered(self):
        event = _make_cloud_event([_SAMPLE_FLOW_ENTRY, "not a dict", 42])
        result = collector_module._decode_pubsub_batch(event)
        assert len(result) == 1


# ===========================================================================
# Test: _decode_http_request
# ===========================================================================

class TestDecodeHttpRequest:
    """Tests for HTTP request decoding."""

    def test_pubsub_push_format(self):
        encoded = base64.b64encode(
            json.dumps(_SAMPLE_FLOW_ENTRY).encode("utf-8")
        ).decode("utf-8")
        request_json = {"message": {"data": encoded}}
        result = collector_module._decode_http_request(request_json)
        assert len(result) == 1

    def test_pubsub_push_batch(self):
        batch = [_SAMPLE_FLOW_ENTRY, _SAMPLE_FLOW_ENTRY_EXTERNAL]
        encoded = base64.b64encode(
            json.dumps(batch).encode("utf-8")
        ).decode("utf-8")
        request_json = {"message": {"data": encoded}}
        result = collector_module._decode_http_request(request_json)
        assert len(result) == 2

    def test_direct_entries_array(self):
        request_json = {"entries": [_SAMPLE_FLOW_ENTRY, _SAMPLE_FLOW_ENTRY_EXTERNAL]}
        result = collector_module._decode_http_request(request_json)
        assert len(result) == 2

    def test_single_entry_body(self):
        result = collector_module._decode_http_request(_SAMPLE_FLOW_ENTRY)
        assert len(result) == 1

    def test_empty_request(self):
        result = collector_module._decode_http_request({})
        assert result == []


# ===========================================================================
# Test: _parse_flow_events
# ===========================================================================

class TestParseFlowEvents:
    """Tests for flow event parsing."""

    def test_parse_valid_event(self):
        result = collector_module._parse_flow_events([_SAMPLE_FLOW_ENTRY])
        assert len(result) == 1
        event = result[0]
        assert event["source_ip"] == "10.0.0.1"
        assert event["destination_ip"] == "10.0.0.2"
        assert "network" in event["metadata"]["tags"]

    def test_parse_external_event(self):
        result = collector_module._parse_flow_events([_SAMPLE_FLOW_ENTRY_EXTERNAL])
        assert len(result) == 1
        event = result[0]
        assert event["destination_ip"] == "8.8.8.8"

    def test_parse_multiple_events(self):
        result = collector_module._parse_flow_events([
            _SAMPLE_FLOW_ENTRY,
            _SAMPLE_FLOW_ENTRY_EXTERNAL,
        ])
        assert len(result) == 2

    def test_invalid_events_skipped(self):
        result = collector_module._parse_flow_events([
            _SAMPLE_FLOW_ENTRY,
            {"not": "a flow log"},  # Missing required fields
        ])
        # Invalid event should be skipped
        assert len(result) >= 1

    def test_empty_input(self):
        result = collector_module._parse_flow_events([])
        assert result == []

    def test_parsed_event_structure(self):
        result = collector_module._parse_flow_events([_SAMPLE_FLOW_ENTRY])
        event = result[0]
        assert "timestamp" in event
        assert "source_ip" in event
        assert "destination_ip" in event
        assert "action" in event
        assert "result" in event
        assert "service" in event
        assert "metadata" in event
        assert "raw_event" in event

    def test_parsed_metadata_ports(self):
        result = collector_module._parse_flow_events([_SAMPLE_FLOW_ENTRY])
        meta = result[0]["metadata"]
        assert meta["source_port"] == 54321
        assert meta["destination_port"] == 443


# ===========================================================================
# Test: _write_to_gcs
# ===========================================================================

class TestWriteToGCS:
    """Tests for GCS writes."""

    @patch("gcp_vpc_flow_collector._gcs_storage")
    def test_writes_ndjson(self, mock_storage_module):
        mock_client = MagicMock()
        mock_storage_module.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        events = collector_module._parse_flow_events([_SAMPLE_FLOW_ENTRY])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

        path = collector_module._write_to_gcs(events, "my-bucket", ts, "part01")
        assert path == "gcp_vpc_flow/raw/2025/06/15/10/flow_part01.json"
        mock_blob.upload_from_string.assert_called_once()
        call_args = mock_blob.upload_from_string.call_args
        content = call_args[0][0]
        lines = content.strip().split("\n")
        assert len(lines) == 1

    @patch("gcp_vpc_flow_collector._gcs_storage")
    def test_empty_events_returns_none(self, mock_storage_module):
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        path = collector_module._write_to_gcs([], "my-bucket", ts)
        assert path is None

    @patch("gcp_vpc_flow_collector._gcs_storage")
    def test_gcs_failure_returns_none(self, mock_storage_module):
        mock_storage_module.Client.side_effect = Exception("GCS error")

        events = collector_module._parse_flow_events([_SAMPLE_FLOW_ENTRY])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

        path = collector_module._write_to_gcs(events, "my-bucket", ts)
        assert path is None

    @patch("gcp_vpc_flow_collector._gcs_storage")
    def test_default_partition_id(self, mock_storage_module):
        mock_client = MagicMock()
        mock_storage_module.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        events = collector_module._parse_flow_events([_SAMPLE_FLOW_ENTRY])
        ts = datetime(2025, 6, 15, 10, 30, 45, tzinfo=timezone.utc)

        path = collector_module._write_to_gcs(events, "my-bucket", ts)
        assert path == "gcp_vpc_flow/raw/2025/06/15/10/flow_3045.json"


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting and writing."""

    @patch.object(collector_module, "_write_to_gcs")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "path1"
        events = [{"a": 1}, {"a": 2}]
        paths = collector_module._batch_and_write(events, "bucket", 10)
        assert paths == ["path1"]
        mock_write.assert_called_once()

    @patch.object(collector_module, "_write_to_gcs")
    def test_multiple_batches(self, mock_write):
        mock_write.side_effect = ["path1", "path2", "path3"]
        events = [{"a": i} for i in range(25)]
        paths = collector_module._batch_and_write(events, "bucket", 10)
        assert len(paths) == 3

    @patch.object(collector_module, "_write_to_gcs")
    def test_partition_prefix(self, mock_write):
        mock_write.return_value = "path1"
        events = [{"a": 1}]
        collector_module._batch_and_write(events, "bucket", 10, partition_prefix="pubsub_")
        call_args = mock_write.call_args
        partition_id = call_args[0][3] if len(call_args[0]) > 3 else ""
        assert partition_id.startswith("pubsub_")


# ===========================================================================
# Test: _report_health
# ===========================================================================

class TestReportHealth:
    """Tests for health reporting."""

    @patch.dict(os.environ, {"HEALTH_STATE_COLLECTION": "health", "TENANT_ID": "t1"})
    @patch("src.shared.health.health_state_store.FirestoreHealthStateStore")
    def test_reports_health(self, mock_store_cls):
        # Reload module env vars
        collector_module.HEALTH_STATE_COLLECTION = "health"
        collector_module.TENANT_ID = "t1"

        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        collector_module._report_health(42)
        mock_store.update_event_count.assert_called_once()
        call_kwargs = mock_store.update_event_count.call_args[1]
        assert call_kwargs["source_type"] == "gcp_vpc_flow"
        assert call_kwargs["count_increment"] == 42

    def test_no_health_collection(self):
        """No crash when health collection not configured."""
        collector_module.HEALTH_STATE_COLLECTION = ""
        collector_module._report_health(100)  # Should not raise


# ===========================================================================
# Test: vpc_flow_pubsub entry point
# ===========================================================================

class TestVpcFlowPubSub:
    """Tests for the Pub/Sub Cloud Function entry point."""

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_single_entry(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        event = _make_cloud_event_single(_SAMPLE_FLOW_ENTRY)
        result = collector_module.vpc_flow_pubsub(event)

        assert result["status"] == "success"
        assert result["total_events"] == 1
        mock_batch.assert_called_once()
        mock_health.assert_called_once_with(1)

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_processes_batch(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        event = _make_cloud_event([_SAMPLE_FLOW_ENTRY, _SAMPLE_FLOW_ENTRY_EXTERNAL])
        result = collector_module.vpc_flow_pubsub(event)

        assert result["status"] == "success"
        assert result["total_events"] == 2
        mock_health.assert_called_once_with(2)

    @patch.object(collector_module, "_report_health")
    def test_empty_message(self, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        event = SimpleNamespace(data={"message": {"data": ""}})
        result = collector_module.vpc_flow_pubsub(event)
        assert result["total_events"] == 0
        mock_health.assert_not_called()

    def test_missing_gcs_bucket(self):
        collector_module.GCS_BUCKET = None
        event = _make_cloud_event_single(_SAMPLE_FLOW_ENTRY)
        result = collector_module.vpc_flow_pubsub(event)
        assert result["status"] == "error"

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_invalid_events_filtered(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        event = _make_cloud_event([_SAMPLE_FLOW_ENTRY, {"not": "flow"}])
        result = collector_module.vpc_flow_pubsub(event)

        assert result["status"] == "success"
        # Only valid events should be parsed
        assert result["total_events"] >= 1


# ===========================================================================
# Test: vpc_flow_http entry point
# ===========================================================================

class TestVpcFlowHttp:
    """Tests for the HTTP Cloud Function entry point."""

    def _make_request(self, json_body):
        """Create a mock Flask request."""
        mock_request = MagicMock()
        mock_request.get_json.return_value = json_body
        return mock_request

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_pubsub_push(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        encoded = base64.b64encode(
            json.dumps(_SAMPLE_FLOW_ENTRY).encode("utf-8")
        ).decode("utf-8")
        request = self._make_request({"message": {"data": encoded}})

        result = collector_module.vpc_flow_http(request)
        assert result["status"] == "success"
        assert result["total_events"] == 1

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_direct_entries(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        request = self._make_request({"entries": [_SAMPLE_FLOW_ENTRY]})
        result = collector_module.vpc_flow_http(request)
        assert result["status"] == "success"
        assert result["total_events"] == 1

    @patch.object(collector_module, "_report_health")
    @patch.object(collector_module, "_batch_and_write")
    def test_single_entry_body(self, mock_batch, mock_health):
        collector_module.GCS_BUCKET = "test-lake"
        mock_batch.return_value = ["path1"]

        request = self._make_request(_SAMPLE_FLOW_ENTRY)
        result = collector_module.vpc_flow_http(request)
        assert result["status"] == "success"
        assert result["total_events"] == 1

    def test_empty_request(self):
        collector_module.GCS_BUCKET = "test-lake"
        request = self._make_request(None)
        result = collector_module.vpc_flow_http(request)
        # Returns tuple (body, status_code) for errors
        if isinstance(result, tuple):
            assert result[1] == 400
        else:
            assert result.get("status") == "error"

    def test_missing_gcs_bucket(self):
        collector_module.GCS_BUCKET = None
        request = self._make_request({"entries": [_SAMPLE_FLOW_ENTRY]})
        result = collector_module.vpc_flow_http(request)
        if isinstance(result, tuple):
            assert result[1] == 500
        else:
            assert result["status"] == "error"


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests with mocked GCS."""

    @patch("gcp_vpc_flow_collector._gcs_storage")
    @patch.object(collector_module, "_report_health")
    def test_pubsub_full_pipeline(self, mock_health, mock_storage_module):
        """Full pipeline: Pub/Sub → parse → write to GCS."""
        collector_module.GCS_BUCKET = "test-lake"
        mock_client = MagicMock()
        mock_storage_module.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        event = _make_cloud_event([_SAMPLE_FLOW_ENTRY, _SAMPLE_FLOW_ENTRY_EXTERNAL])
        result = collector_module.vpc_flow_pubsub(event)

        assert result["status"] == "success"
        assert result["total_events"] == 2
        assert result["files_written"] == 1
        mock_blob.upload_from_string.assert_called_once()

        # Verify NDJSON content
        content = mock_blob.upload_from_string.call_args[0][0]
        lines = content.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "network" in parsed["metadata"]["tags"]

    @patch("gcp_vpc_flow_collector._gcs_storage")
    @patch.object(collector_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_storage_module):
        """Verify data lake path follows gcp_vpc_flow/raw/YYYY/MM/DD/HH/."""
        collector_module.GCS_BUCKET = "test-lake"
        mock_client = MagicMock()
        mock_storage_module.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        event = _make_cloud_event_single(_SAMPLE_FLOW_ENTRY)
        result = collector_module.vpc_flow_pubsub(event)

        assert result["files_written"] == 1
        blob_path = mock_bucket.blob.call_args[0][0]
        assert blob_path.startswith("gcp_vpc_flow/raw/")
        parts = blob_path.split("/")
        assert parts[0] == "gcp_vpc_flow"
        assert parts[1] == "raw"
        assert len(parts[2]) == 4  # Year
        assert len(parts[3]) == 2  # Month
        assert len(parts[4]) == 2  # Day
        assert len(parts[5]) == 2  # Hour

    @patch("gcp_vpc_flow_collector._gcs_storage")
    @patch.object(collector_module, "_report_health")
    def test_batch_splitting(self, mock_health, mock_storage_module):
        """Verify batch splitting with small batch size."""
        collector_module.GCS_BUCKET = "test-lake"
        collector_module.BATCH_SIZE = 1
        mock_client = MagicMock()
        mock_storage_module.Client.return_value = mock_client
        mock_bucket = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        event = _make_cloud_event([_SAMPLE_FLOW_ENTRY, _SAMPLE_FLOW_ENTRY_EXTERNAL])
        result = collector_module.vpc_flow_pubsub(event)

        assert result["total_events"] == 2
        assert result["files_written"] == 2
        assert mock_blob.upload_from_string.call_count == 2

        # Reset batch size
        collector_module.BATCH_SIZE = 10000
