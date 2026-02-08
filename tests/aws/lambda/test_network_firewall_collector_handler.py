"""Unit tests for the AWS Network Firewall Log Collector Lambda."""

import base64
import gzip
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# Ensure the Lambda directory is on the path
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/aws/lambda")
)
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/shared")
)

import network_firewall_collector_handler as handler_module


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_SAMPLE_AWS_FW_ALERT = {
    "firewall_name": "my-firewall",
    "availability_zone": "us-east-1a",
    "event_timestamp": "1718442000",
    "event": {
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
    },
}

_SAMPLE_AWS_FW_FLOW = {
    "firewall_name": "my-firewall",
    "availability_zone": "us-east-1a",
    "event_timestamp": "1718442060",
    "event": {
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
    },
}

_SAMPLE_AWS_FW_DROP = {
    "firewall_name": "my-firewall",
    "availability_zone": "us-east-1b",
    "event_timestamp": "1718442120",
    "event": {
        "timestamp": "2025-06-15T10:02:00.000000+0000",
        "event_type": "drop",
        "src_ip": "192.168.1.100",
        "src_port": 8888,
        "dest_ip": "172.16.0.50",
        "dest_port": 22,
        "proto": "TCP",
    },
}


def _make_cloudwatch_event(entries):
    """Create a simulated CloudWatch Logs subscription filter event."""
    messages = [json.dumps(e) for e in entries]
    log_events = [{"message": m, "id": str(i)} for i, m in enumerate(messages)]
    payload = {"logEvents": log_events, "logGroup": "/aws/network-firewall/flow"}
    compressed = gzip.compress(json.dumps(payload).encode("utf-8"))
    encoded = base64.b64encode(compressed).decode("utf-8")
    return {"awslogs": {"data": encoded}}


def _make_s3_event(bucket, key):
    """Create a simulated S3 event notification."""
    return {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {"key": key},
                }
            }
        ]
    }


def _make_sqs_wrapped_s3_event(bucket, key):
    """Create a simulated SQS-wrapped S3 event."""
    inner = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {"key": key},
                }
            }
        ]
    }
    return {"Records": [{"body": json.dumps(inner)}]}


# ===========================================================================
# Test: _read_s3_file
# ===========================================================================

class TestReadS3File:
    """Tests for S3 file reading."""

    @patch.object(handler_module, "_get_s3")
    def test_reads_ndjson(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        content = "\n".join(
            [json.dumps(_SAMPLE_AWS_FW_ALERT), json.dumps(_SAMPLE_AWS_FW_FLOW)]
        )
        mock_s3.get_object.return_value = {
            "Body": MagicMock(read=lambda: content.encode("utf-8"))
        }

        result = handler_module._read_s3_file("bucket", "key.json")
        assert len(result) == 2

    @patch.object(handler_module, "_get_s3")
    def test_reads_gzipped(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        content = json.dumps(_SAMPLE_AWS_FW_ALERT).encode("utf-8")
        compressed = gzip.compress(content)
        mock_s3.get_object.return_value = {
            "Body": MagicMock(read=lambda: compressed)
        }

        result = handler_module._read_s3_file("bucket", "key.json.gz")
        assert len(result) == 1

    @patch.object(handler_module, "_get_s3")
    def test_invalid_content_returns_empty(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3
        mock_s3.get_object.side_effect = Exception("S3 error")
        assert handler_module._read_s3_file("bucket", "key.json") == []


# ===========================================================================
# Test: _decode_cloudwatch_logs
# ===========================================================================

class TestDecodeCloudWatchLogs:
    """Tests for CloudWatch Logs decoding."""

    def test_decode_valid_events(self):
        event = _make_cloudwatch_event([_SAMPLE_AWS_FW_ALERT])
        result = handler_module._decode_cloudwatch_logs(event)
        assert len(result) == 1

    def test_decode_multiple(self):
        event = _make_cloudwatch_event(
            [_SAMPLE_AWS_FW_ALERT, _SAMPLE_AWS_FW_FLOW]
        )
        result = handler_module._decode_cloudwatch_logs(event)
        assert len(result) == 2

    def test_empty_data(self):
        event = {"awslogs": {"data": ""}}
        assert handler_module._decode_cloudwatch_logs(event) == []


# ===========================================================================
# Test: _extract_s3_events
# ===========================================================================

class TestExtractS3Events:
    """Tests for S3 event extraction."""

    def test_direct_s3_event(self):
        event = _make_s3_event("my-bucket", "logs/fw.json")
        refs = handler_module._extract_s3_events(event)
        assert len(refs) == 1
        assert refs[0]["bucket"] == "my-bucket"
        assert refs[0]["key"] == "logs/fw.json"

    def test_sqs_wrapped(self):
        event = _make_sqs_wrapped_s3_event("my-bucket", "logs/fw.json")
        refs = handler_module._extract_s3_events(event)
        assert len(refs) == 1

    def test_empty_records(self):
        assert handler_module._extract_s3_events({"Records": []}) == []


# ===========================================================================
# Test: _parse_firewall_events
# ===========================================================================

class TestParseFirewallEvents:
    """Tests for firewall event parsing."""

    def test_parse_alert(self):
        result = handler_module._parse_firewall_events([_SAMPLE_AWS_FW_ALERT])
        assert len(result) == 1
        event = result[0]
        assert event["source_ip"] == "10.0.0.4"
        assert "firewall" in event["metadata"]["tags"]

    def test_parse_flow(self):
        result = handler_module._parse_firewall_events([_SAMPLE_AWS_FW_FLOW])
        assert len(result) == 1

    def test_parse_multiple(self):
        result = handler_module._parse_firewall_events(
            [_SAMPLE_AWS_FW_ALERT, _SAMPLE_AWS_FW_FLOW, _SAMPLE_AWS_FW_DROP]
        )
        assert len(result) == 3

    def test_invalid_events_skipped(self):
        result = handler_module._parse_firewall_events(
            [_SAMPLE_AWS_FW_ALERT, {"not": "a firewall log"}]
        )
        assert len(result) >= 1

    def test_empty_input(self):
        assert handler_module._parse_firewall_events([]) == []


# ===========================================================================
# Test: _write_to_data_lake
# ===========================================================================

class TestWriteToDataLake:
    """Tests for data lake writes."""

    @patch.object(handler_module, "_get_s3")
    def test_writes_ndjson(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        events = handler_module._parse_firewall_events([_SAMPLE_AWS_FW_ALERT])
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)

        key = handler_module._write_to_data_lake(
            events, "my-bucket", ts, "part01"
        )
        assert key == "network_firewall/raw/2025/06/15/10/fw_part01.json"
        mock_s3.put_object.assert_called_once()

    @patch.object(handler_module, "_get_s3")
    def test_empty_events_returns_none(self, mock_get_s3):
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert handler_module._write_to_data_lake([], "bucket", ts) is None

    @patch.object(handler_module, "_get_s3")
    def test_s3_failure_returns_none(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3
        mock_s3.put_object.side_effect = Exception("S3 error")

        events = handler_module._parse_firewall_events([_SAMPLE_AWS_FW_ALERT])
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert handler_module._write_to_data_lake(events, "bucket", ts) is None


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting."""

    @patch.object(handler_module, "_write_to_data_lake")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "key1"
        keys = handler_module._batch_and_write([{"a": 1}], "bucket", 10)
        assert keys == ["key1"]

    @patch.object(handler_module, "_write_to_data_lake")
    def test_multiple_batches(self, mock_write):
        mock_write.side_effect = ["k1", "k2", "k3"]
        events = [{"a": i} for i in range(25)]
        keys = handler_module._batch_and_write(events, "bucket", 10)
        assert len(keys) == 3


# ===========================================================================
# Test: _report_health
# ===========================================================================

class TestReportHealth:
    """Tests for health reporting."""

    @patch("src.shared.health.health_state_store.DynamoDBHealthStateStore")
    def test_reports_health(self, mock_store_cls):
        os.environ["LOG_SOURCE_HEALTH_TABLE"] = "health-table"
        os.environ["TENANT_ID"] = "t1"
        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store

        handler_module._report_health(50)
        mock_store.update_event_count.assert_called_once()
        assert (
            mock_store.update_event_count.call_args[1]["source_type"]
            == "network_firewall"
        )

        os.environ.pop("LOG_SOURCE_HEALTH_TABLE", None)

    def test_no_health_table(self):
        os.environ.pop("LOG_SOURCE_HEALTH_TABLE", None)
        handler_module._report_health(100)  # No crash


# ===========================================================================
# Test: Checkpoint management
# ===========================================================================

class TestCheckpoints:
    """Tests for checkpoint management."""

    @patch.object(handler_module, "_get_dynamodb")
    def test_is_processed_true(self, mock_get_ddb):
        os.environ["CHECKPOINT_TABLE"] = "checkpoints"
        mock_table = MagicMock()
        mock_get_ddb.return_value.Table.return_value = mock_table
        mock_table.get_item.return_value = {
            "Item": {"source": "network_firewall:bucket/key"}
        }
        assert handler_module._is_processed("bucket/key") is True
        os.environ.pop("CHECKPOINT_TABLE", None)

    @patch.object(handler_module, "_get_dynamodb")
    def test_is_processed_false(self, mock_get_ddb):
        os.environ["CHECKPOINT_TABLE"] = "checkpoints"
        mock_table = MagicMock()
        mock_get_ddb.return_value.Table.return_value = mock_table
        mock_table.get_item.return_value = {}
        assert handler_module._is_processed("bucket/key") is False
        os.environ.pop("CHECKPOINT_TABLE", None)

    def test_no_checkpoint_table(self):
        os.environ.pop("CHECKPOINT_TABLE", None)
        assert handler_module._is_processed("key") is False

    @patch.object(handler_module, "_get_dynamodb")
    def test_save_checkpoint(self, mock_get_ddb):
        os.environ["CHECKPOINT_TABLE"] = "checkpoints"
        mock_table = MagicMock()
        mock_get_ddb.return_value.Table.return_value = mock_table
        handler_module._save_checkpoint("bucket/key")
        mock_table.put_item.assert_called_once()
        os.environ.pop("CHECKPOINT_TABLE", None)


# ===========================================================================
# Test: lambda_handler — CloudWatch Subscription
# ===========================================================================

class TestLambdaHandlerCloudWatch:
    """Tests for the CloudWatch Logs subscription path."""

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    def test_processes_events(self, mock_batch, mock_health):
        os.environ["LOGS_BUCKET"] = "test-lake"
        mock_batch.return_value = ["key1"]

        event = _make_cloudwatch_event(
            [_SAMPLE_AWS_FW_ALERT, _SAMPLE_AWS_FW_FLOW]
        )
        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        assert result["mode"] == "cloudwatch_subscription"
        assert result["total_events"] == 2
        mock_health.assert_called_once_with(2)

        os.environ.pop("LOGS_BUCKET", None)

    @patch.object(handler_module, "_report_health")
    def test_empty_cloudwatch(self, mock_health):
        os.environ["LOGS_BUCKET"] = "test-lake"
        payload = {"logEvents": [], "logGroup": "/test"}
        compressed = gzip.compress(json.dumps(payload).encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")
        event = {"awslogs": {"data": encoded}}

        result = handler_module.lambda_handler(event, None)
        assert result["total_events"] == 0
        mock_health.assert_not_called()

        os.environ.pop("LOGS_BUCKET", None)


# ===========================================================================
# Test: lambda_handler — S3 Event
# ===========================================================================

class TestLambdaHandlerS3:
    """Tests for the S3 event path."""

    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_is_processed", return_value=False)
    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_read_s3_file")
    def test_processes_s3_file(
        self, mock_read, mock_batch, mock_health, mock_check, mock_save
    ):
        os.environ["LOGS_BUCKET"] = "test-lake"
        mock_read.return_value = [_SAMPLE_AWS_FW_ALERT, _SAMPLE_AWS_FW_FLOW]
        mock_batch.return_value = ["key1"]

        event = _make_s3_event("source-bucket", "logs/fw.json")
        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        assert result["mode"] == "s3_event"
        assert result["total_events"] == 2
        mock_health.assert_called_once_with(2)
        mock_save.assert_called_once()

        os.environ.pop("LOGS_BUCKET", None)

    @patch.object(handler_module, "_is_processed", return_value=True)
    @patch.object(handler_module, "_report_health")
    def test_skips_processed_file(self, mock_health, mock_check):
        os.environ["LOGS_BUCKET"] = "test-lake"
        event = _make_s3_event("source-bucket", "logs/fw.json")
        result = handler_module.lambda_handler(event, None)

        assert result["total_events"] == 0
        mock_health.assert_not_called()

        os.environ.pop("LOGS_BUCKET", None)

    def test_unknown_event_format(self):
        os.environ["LOGS_BUCKET"] = "test-lake"
        result = handler_module.lambda_handler({"custom": "data"}, None)
        assert result["statusCode"] == 400
        os.environ.pop("LOGS_BUCKET", None)


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests."""

    @patch.object(handler_module, "_get_s3")
    @patch.object(handler_module, "_report_health")
    def test_cloudwatch_full_pipeline(self, mock_health, mock_get_s3):
        os.environ["LOGS_BUCKET"] = "test-lake"
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        event = _make_cloudwatch_event(
            [_SAMPLE_AWS_FW_ALERT, _SAMPLE_AWS_FW_FLOW, _SAMPLE_AWS_FW_DROP]
        )
        result = handler_module.lambda_handler(event, None)

        assert result["total_events"] == 3
        assert result["files_written"] == 1
        mock_s3.put_object.assert_called_once()

        content = mock_s3.put_object.call_args[1]["Body"].decode("utf-8")
        lines = content.strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "firewall" in parsed["metadata"]["tags"]

        os.environ.pop("LOGS_BUCKET", None)

    @patch.object(handler_module, "_get_s3")
    @patch.object(handler_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_get_s3):
        os.environ["LOGS_BUCKET"] = "test-lake"
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        event = _make_cloudwatch_event([_SAMPLE_AWS_FW_ALERT])
        handler_module.lambda_handler(event, None)

        s3_key = mock_s3.put_object.call_args[1]["Key"]
        assert s3_key.startswith("network_firewall/raw/")
        parts = s3_key.split("/")
        assert parts[0] == "network_firewall"
        assert parts[1] == "raw"

        os.environ.pop("LOGS_BUCKET", None)
