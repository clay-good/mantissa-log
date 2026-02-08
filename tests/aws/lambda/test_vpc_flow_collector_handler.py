"""Unit tests for the AWS VPC Flow Log Collector handler."""

import base64
import gzip
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

import pytest

# Ensure the Lambda handler directory is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/aws/lambda"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/shared"))

import vpc_flow_collector_handler as handler_module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_globals():
    """Reset global state between tests."""
    handler_module._s3_client = None
    handler_module._dynamodb_resource = None
    yield


@pytest.fixture
def env_vars(monkeypatch):
    """Set environment variables."""
    monkeypatch.setenv("LOGS_BUCKET", "test-data-lake")
    monkeypatch.setenv("LOG_SOURCE_HEALTH_TABLE", "test-health-table")
    monkeypatch.setenv("TENANT_ID", "test-tenant")
    monkeypatch.setenv("CHECKPOINT_TABLE", "test-checkpoints")
    monkeypatch.setenv("BATCH_SIZE", "5000")
    monkeypatch.setenv("SOURCE_BUCKET", "test-source-bucket")
    monkeypatch.setenv("SOURCE_PREFIX", "vpc-flow-logs/")


# ---------------------------------------------------------------------------
# Sample flow log data
# ---------------------------------------------------------------------------

_V2_HEADER = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"

_V2_LINE = "2 123456789012 eni-abc123 10.0.0.4 93.184.216.34 54321 443 6 10 1024 1718442000 1718442060 ACCEPT OK"

_V2_LINE_REJECT = "2 123456789012 eni-abc123 93.184.216.34 10.0.0.4 443 22 6 5 512 1718442000 1718442030 REJECT OK"

_V5_HEADER = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status vpc-id subnet-id instance-id tcp-flags type pkt-srcaddr pkt-dstaddr"

_V5_LINE = "5 123456789012 eni-abc123 10.0.0.4 93.184.216.34 54321 443 6 10 1024 1718442000 1718442060 ACCEPT OK vpc-abc subnet-123 i-abc123 2 IPv4 10.0.0.4 93.184.216.34"

_CUSTOM_HEADER = "srcaddr dstaddr srcport dstport version account-id interface-id protocol packets bytes start end action log-status"
_CUSTOM_LINE = "10.0.0.4 93.184.216.34 54321 443 2 123456789012 eni-abc123 6 10 1024 1718442000 1718442060 ACCEPT OK"


def _make_s3_event(bucket="test-flow-logs", key="vpc-flow-logs/eni-abc123/2024/06/15/flow.log.gz"):
    """Build a synthetic S3 event notification."""
    return {
        "Records": [
            {
                "eventSource": "aws:s3",
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {"key": key},
                },
            }
        ]
    }


def _make_sqs_s3_event(bucket="test-flow-logs", key="vpc-flow-logs/flow.log.gz"):
    """Build a synthetic SQS event wrapping an S3 notification."""
    s3_event = {
        "Records": [
            {
                "eventSource": "aws:s3",
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {"key": key},
                },
            }
        ]
    }
    return {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "body": json.dumps(s3_event),
            }
        ]
    }


def _make_cloudwatch_logs_event(lines):
    """Build a synthetic CloudWatch Logs subscription filter event."""
    payload = {
        "logGroup": "/aws/vpc-flow-logs",
        "logStream": "eni-abc123",
        "logEvents": [
            {"id": str(i), "timestamp": 1718442000000, "message": line}
            for i, line in enumerate(lines)
        ],
    }
    compressed = gzip.compress(json.dumps(payload).encode("utf-8"))
    encoded = base64.b64encode(compressed).decode("utf-8")
    return {"awslogs": {"data": encoded}}


def _gzip_content(text):
    """Gzip compress text."""
    return gzip.compress(text.encode("utf-8"))


# ===========================================================================
# Header detection
# ===========================================================================

class TestDetectHeader:
    """_detect_header tests."""

    def test_v2_header(self):
        lines = [_V2_HEADER, _V2_LINE]
        fields, data = handler_module._detect_header(lines)
        assert fields is not None
        assert len(fields) == 14
        assert fields[0] == "version"
        assert len(data) == 1

    def test_v5_header(self):
        lines = [_V5_HEADER, _V5_LINE]
        fields, data = handler_module._detect_header(lines)
        assert fields is not None
        assert len(fields) > 14

    def test_no_header(self):
        lines = [_V2_LINE]
        fields, data = handler_module._detect_header(lines)
        assert fields is None
        assert len(data) == 1

    def test_empty_lines(self):
        fields, data = handler_module._detect_header([])
        assert fields is None
        assert data == []

    def test_custom_header_order(self):
        lines = [_CUSTOM_HEADER, _CUSTOM_LINE]
        fields, data = handler_module._detect_header(lines)
        assert fields is not None
        assert fields[0] == "srcaddr"  # Custom order
        assert len(data) == 1


# ===========================================================================
# Reconstruct flow line
# ===========================================================================

class TestReconstructFlowLine:
    """_reconstruct_flow_line tests."""

    def test_default_order_passthrough(self):
        """When field order matches v2 default, return as-is."""
        result = handler_module._reconstruct_flow_line(
            handler_module._V2_DEFAULT_FIELDS, _V2_LINE
        )
        assert result == _V2_LINE

    def test_custom_order_reordered(self):
        """Custom field order should be re-mapped to v2 positional format."""
        fields = _CUSTOM_HEADER.split()
        result = handler_module._reconstruct_flow_line(fields, _CUSTOM_LINE)
        parts = result.split()
        # After reordering, first field should be version ("2")
        assert parts[0] == "2"
        # srcaddr should be at index 3
        assert parts[3] == "10.0.0.4"
        # dstaddr should be at index 4
        assert parts[4] == "93.184.216.34"

    def test_mismatched_field_count(self):
        """If field count doesn't match, return raw line."""
        fields = ["version", "srcaddr"]
        result = handler_module._reconstruct_flow_line(fields, _V2_LINE)
        assert result == _V2_LINE


# ===========================================================================
# Parse flow lines
# ===========================================================================

class TestParseFlowLines:
    """_parse_flow_lines tests."""

    def test_parse_v2_lines(self):
        lines = [_V2_LINE]
        parsed = handler_module._parse_flow_lines(lines, field_names=None)
        assert len(parsed) == 1
        assert parsed[0]["source_ip"] == "10.0.0.4"
        assert parsed[0]["destination_ip"] == "93.184.216.34"
        assert parsed[0]["service"] == "vpc"

    def test_parse_with_v2_header_fields(self):
        fields = _V2_HEADER.split()
        parsed = handler_module._parse_flow_lines([_V2_LINE], field_names=fields)
        assert len(parsed) == 1
        assert parsed[0]["source_ip"] == "10.0.0.4"

    def test_skip_header_lines(self):
        """Lines starting with 'version' should be skipped."""
        lines = [_V2_HEADER, _V2_LINE]
        parsed = handler_module._parse_flow_lines(lines, field_names=None)
        assert len(parsed) == 1

    def test_skip_empty_lines(self):
        lines = ["", "  ", _V2_LINE, ""]
        parsed = handler_module._parse_flow_lines(lines, field_names=None)
        assert len(parsed) == 1

    def test_skip_invalid_lines(self):
        lines = ["not a flow log", _V2_LINE]
        parsed = handler_module._parse_flow_lines(lines, field_names=None)
        assert len(parsed) == 1

    def test_multiple_lines(self):
        lines = [_V2_LINE, _V2_LINE_REJECT]
        parsed = handler_module._parse_flow_lines(lines, field_names=None)
        assert len(parsed) == 2

    def test_accept_result(self):
        parsed = handler_module._parse_flow_lines([_V2_LINE], field_names=None)
        assert parsed[0]["result"] == "success"

    def test_reject_result(self):
        parsed = handler_module._parse_flow_lines([_V2_LINE_REJECT], field_names=None)
        assert parsed[0]["result"] == "failure"


# ===========================================================================
# Flow aggregation
# ===========================================================================

class TestAggregateFlows:
    """_aggregate_flows tests."""

    def test_no_aggregation_different_tuples(self):
        events = [
            {
                "source_ip": "10.0.0.4", "destination_ip": "93.184.216.34",
                "metadata": {
                    "source_port": 54321, "destination_port": 443,
                    "protocol_name": "TCP", "start": 1718442000,
                    "bytes": 1024, "bytes_transferred": 1024,
                    "packets": 10, "duration_seconds": 60,
                },
            },
            {
                "source_ip": "10.0.0.5", "destination_ip": "93.184.216.34",
                "metadata": {
                    "source_port": 54322, "destination_port": 443,
                    "protocol_name": "TCP", "start": 1718442000,
                    "bytes": 2048, "bytes_transferred": 2048,
                    "packets": 20, "duration_seconds": 30,
                },
            },
        ]
        result = handler_module._aggregate_flows(events, window_seconds=300)
        assert len(result) == 2

    def test_aggregation_same_tuple(self):
        events = [
            {
                "source_ip": "10.0.0.4", "destination_ip": "93.184.216.34",
                "metadata": {
                    "source_port": 54321, "destination_port": 443,
                    "protocol_name": "TCP", "start": 1718442000,
                    "bytes": 1024, "bytes_transferred": 1024,
                    "packets": 10, "duration_seconds": 60,
                },
            },
            {
                "source_ip": "10.0.0.4", "destination_ip": "93.184.216.34",
                "metadata": {
                    "source_port": 54321, "destination_port": 443,
                    "protocol_name": "TCP", "start": 1718442100,
                    "bytes": 2048, "bytes_transferred": 2048,
                    "packets": 20, "duration_seconds": 30,
                },
            },
        ]
        result = handler_module._aggregate_flows(events, window_seconds=300)
        assert len(result) == 1
        assert result[0]["metadata"]["bytes"] == 3072
        assert result[0]["metadata"]["bytes_transferred"] == 3072
        assert result[0]["metadata"]["packets"] == 30
        assert result[0]["metadata"]["duration_seconds"] == 60
        assert result[0]["metadata"]["aggregated_count"] == 2

    def test_aggregation_different_windows(self):
        events = [
            {
                "source_ip": "10.0.0.4", "destination_ip": "93.184.216.34",
                "metadata": {
                    "source_port": 54321, "destination_port": 443,
                    "protocol_name": "TCP", "start": 1718442000,
                    "bytes": 1024, "bytes_transferred": 1024,
                    "packets": 10, "duration_seconds": 60,
                },
            },
            {
                "source_ip": "10.0.0.4", "destination_ip": "93.184.216.34",
                "metadata": {
                    "source_port": 54321, "destination_port": 443,
                    "protocol_name": "TCP", "start": 1718442600,  # 10 min later
                    "bytes": 2048, "bytes_transferred": 2048,
                    "packets": 20, "duration_seconds": 30,
                },
            },
        ]
        result = handler_module._aggregate_flows(events, window_seconds=300)
        assert len(result) == 2  # Different 5-min windows

    def test_empty_events(self):
        result = handler_module._aggregate_flows([], window_seconds=300)
        assert result == []


# ===========================================================================
# CloudWatch Logs decoding
# ===========================================================================

class TestDecodeCloudWatchLogs:
    """_decode_cloudwatch_logs tests."""

    def test_valid_event(self):
        event = _make_cloudwatch_logs_event([_V2_LINE, _V2_LINE_REJECT])
        lines = handler_module._decode_cloudwatch_logs(event)
        assert len(lines) == 2
        assert lines[0] == _V2_LINE
        assert lines[1] == _V2_LINE_REJECT

    def test_empty_data(self):
        lines = handler_module._decode_cloudwatch_logs({"awslogs": {"data": ""}})
        assert lines == []

    def test_missing_awslogs(self):
        lines = handler_module._decode_cloudwatch_logs({})
        assert lines == []

    def test_invalid_base64(self):
        lines = handler_module._decode_cloudwatch_logs({"awslogs": {"data": "not-base64!"}})
        assert lines == []


# ===========================================================================
# S3 file reading (mocked)
# ===========================================================================

class TestReadS3FlowLogFile:
    """_read_s3_flow_log_file tests."""

    @patch.object(handler_module, "_get_s3")
    def test_read_plain_file(self, mock_get_s3):
        content = f"{_V2_HEADER}\n{_V2_LINE}\n".encode("utf-8")
        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {"Body": MagicMock(read=lambda: content)}
        mock_get_s3.return_value = mock_s3

        lines = handler_module._read_s3_flow_log_file("bucket", "flow.log")
        assert len(lines) == 2

    @patch.object(handler_module, "_get_s3")
    def test_read_gzip_file(self, mock_get_s3):
        content = _gzip_content(f"{_V2_HEADER}\n{_V2_LINE}\n")
        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {"Body": MagicMock(read=lambda: content)}
        mock_get_s3.return_value = mock_s3

        lines = handler_module._read_s3_flow_log_file("bucket", "flow.log.gz")
        assert len(lines) == 2

    @patch.object(handler_module, "_get_s3")
    def test_read_error(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_s3.get_object.side_effect = Exception("S3 error")
        mock_get_s3.return_value = mock_s3

        lines = handler_module._read_s3_flow_log_file("bucket", "flow.log")
        assert lines == []


# ===========================================================================
# Write to data lake (mocked)
# ===========================================================================

class TestWriteToDataLake:
    """_write_to_data_lake tests."""

    @patch.object(handler_module, "_get_s3")
    def test_write_events(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        events = [{"source_ip": "10.0.0.4", "metadata": {}}]
        ts = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        key = handler_module._write_to_data_lake(events, "test-bucket", ts, "part01")

        assert key == "vpc_flow/raw/2024/06/15/10/flow_part01.json"
        mock_s3.put_object.assert_called_once()
        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"] == "vpc_flow/raw/2024/06/15/10/flow_part01.json"

    @patch.object(handler_module, "_get_s3")
    def test_write_empty_events(self, mock_get_s3):
        key = handler_module._write_to_data_lake(
            [], "test-bucket", datetime.now(timezone.utc), "p"
        )
        assert key is None

    @patch.object(handler_module, "_get_s3")
    def test_write_error(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = Exception("S3 error")
        mock_get_s3.return_value = mock_s3

        events = [{"source_ip": "10.0.0.4"}]
        key = handler_module._write_to_data_lake(
            events, "test-bucket", datetime.now(timezone.utc), "p"
        )
        assert key is None


# ===========================================================================
# Batch and write
# ===========================================================================

class TestBatchAndWrite:
    """_batch_and_write tests."""

    @patch.object(handler_module, "_write_to_data_lake")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "vpc_flow/raw/2024/06/15/10/flow_part.json"
        events = [{"source_ip": "10.0.0.4"}] * 3
        keys = handler_module._batch_and_write(events, "bucket", batch_size=10)
        assert len(keys) == 1
        mock_write.assert_called_once()

    @patch.object(handler_module, "_write_to_data_lake")
    def test_multiple_batches(self, mock_write):
        mock_write.return_value = "vpc_flow/raw/2024/06/15/10/flow_part.json"
        events = [{"source_ip": "10.0.0.4"}] * 15
        keys = handler_module._batch_and_write(events, "bucket", batch_size=5)
        assert len(keys) == 3
        assert mock_write.call_count == 3

    @patch.object(handler_module, "_write_to_data_lake")
    def test_empty_events(self, mock_write):
        keys = handler_module._batch_and_write([], "bucket", batch_size=10)
        assert keys == []
        mock_write.assert_not_called()


# ===========================================================================
# Health reporting
# ===========================================================================

class TestReportHealth:
    """_report_health tests."""

    @patch.dict(os.environ, {"LOG_SOURCE_HEALTH_TABLE": "health-table", "TENANT_ID": "t1"})
    @patch("src.shared.health.health_state_store.DynamoDBHealthStateStore")
    def test_reports_health(self, mock_store_cls):
        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        handler_module._report_health(100)
        mock_store.update_event_count.assert_called_once()
        call_kwargs = mock_store.update_event_count.call_args[1]
        assert call_kwargs["source_type"] == "vpc_flow_logs"
        assert call_kwargs["count_increment"] == 100
        assert call_kwargs["tenant_id"] == "t1"

    @patch.dict(os.environ, {}, clear=True)
    def test_no_health_table(self):
        """No crash when health table not configured."""
        handler_module._report_health(100)  # Should not raise


# ===========================================================================
# Lambda handler integration (mocked AWS)
# ===========================================================================

class TestLambdaHandlerS3Event:
    """Lambda handler in S3 event mode."""

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_read_s3_flow_log_file")
    def test_s3_event(self, mock_read, mock_write, mock_health, env_vars):
        mock_read.return_value = [_V2_HEADER, _V2_LINE]
        mock_write.return_value = ["vpc_flow/raw/2024/06/15/10/flow.json"]

        event = _make_s3_event()
        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        assert result["mode"] == "s3_event"
        assert result["total_events"] == 1
        mock_health.assert_called_once_with(1)

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_read_s3_flow_log_file")
    def test_s3_event_empty_file(self, mock_read, mock_write, mock_health, env_vars):
        mock_read.return_value = []
        mock_write.return_value = []

        event = _make_s3_event()
        result = handler_module.lambda_handler(event, None)

        assert result["total_events"] == 0
        mock_health.assert_not_called()


class TestLambdaHandlerSQSS3Event:
    """Lambda handler in SQS-wrapped S3 event mode."""

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_read_s3_flow_log_file")
    def test_sqs_s3_event(self, mock_read, mock_write, mock_health, env_vars):
        mock_read.return_value = [_V2_HEADER, _V2_LINE, _V2_LINE_REJECT]
        mock_write.return_value = ["vpc_flow/raw/2024/06/15/10/flow.json"]

        event = _make_sqs_s3_event()
        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        assert result["mode"] == "sqs_s3_event"
        assert result["total_events"] == 2
        mock_health.assert_called_once_with(2)


class TestLambdaHandlerCloudWatchLogs:
    """Lambda handler in CloudWatch Logs mode."""

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    def test_cloudwatch_event(self, mock_write, mock_health, env_vars):
        mock_write.return_value = ["vpc_flow/raw/2024/06/15/10/flow.json"]

        event = _make_cloudwatch_logs_event([_V2_LINE])
        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        assert result["mode"] == "cloudwatch_logs"
        assert result["total_events"] == 1
        mock_health.assert_called_once_with(1)

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    def test_cloudwatch_empty(self, mock_write, mock_health, env_vars):
        event = _make_cloudwatch_logs_event([])
        result = handler_module.lambda_handler(event, None)

        assert result["total_events"] == 0
        mock_health.assert_not_called()


class TestLambdaHandlerScheduled:
    """Lambda handler in scheduled mode."""

    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_get_checkpoint")
    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_read_s3_flow_log_file")
    @patch.object(handler_module, "_list_unprocessed_files")
    def test_scheduled_mode(
        self, mock_list, mock_read, mock_write, mock_health,
        mock_get_cp, mock_save_cp, env_vars
    ):
        mock_list.return_value = ["vpc-flow-logs/file1.log", "vpc-flow-logs/file2.log"]
        mock_read.return_value = [_V2_HEADER, _V2_LINE]
        mock_write.return_value = ["key1.json"]
        mock_get_cp.return_value = None

        result = handler_module.lambda_handler({}, None)

        assert result["statusCode"] == 200
        assert result["mode"] == "scheduled"
        assert result["files_scanned"] == 2
        assert result["total_events"] == 2
        assert mock_save_cp.call_count == 2

    @patch.object(handler_module, "_list_unprocessed_files")
    @patch.object(handler_module, "_get_checkpoint")
    def test_scheduled_missing_config(self, mock_cp, mock_list, monkeypatch):
        monkeypatch.delenv("SOURCE_BUCKET", raising=False)
        monkeypatch.delenv("SOURCE_PREFIX", raising=False)

        result = handler_module.lambda_handler({}, None)
        assert result["statusCode"] == 400
        mock_list.assert_not_called()


class TestLambdaHandlerWithAggregation:
    """Lambda handler with flow aggregation enabled."""

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    def test_aggregation_enabled(self, mock_write, mock_health, env_vars, monkeypatch):
        monkeypatch.setenv("AGGREGATE_FLOWS", "true")
        monkeypatch.setenv("AGGREGATE_WINDOW_SECONDS", "300")
        mock_write.return_value = ["key.json"]

        # Two identical flow lines → should aggregate to 1
        event = _make_cloudwatch_logs_event([_V2_LINE, _V2_LINE])
        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        # The parsed events get aggregated; check that write was called
        mock_write.assert_called_once()
        # The events passed to batch_and_write
        written_events = mock_write.call_args[0][0]
        assert len(written_events) == 1  # Aggregated from 2 identical
        assert written_events[0]["metadata"]["aggregated_count"] == 2


# ===========================================================================
# Checkpoint management
# ===========================================================================

class TestCheckpoints:
    """Checkpoint get/save tests."""

    @patch.object(handler_module, "_get_dynamodb")
    def test_get_checkpoint(self, mock_ddb, env_vars):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"source": "vpc_flow:default", "last_processed_key": "file1.log"}
        }
        mock_ddb.return_value.Table.return_value = mock_table

        result = handler_module._get_checkpoint("default")
        assert result == "file1.log"

    @patch.object(handler_module, "_get_dynamodb")
    def test_get_checkpoint_not_found(self, mock_ddb, env_vars):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {}
        mock_ddb.return_value.Table.return_value = mock_table

        result = handler_module._get_checkpoint("default")
        assert result is None

    def test_get_checkpoint_no_table(self, monkeypatch):
        monkeypatch.delenv("CHECKPOINT_TABLE", raising=False)
        result = handler_module._get_checkpoint("default")
        assert result is None

    @patch.object(handler_module, "_get_dynamodb")
    def test_save_checkpoint(self, mock_ddb, env_vars):
        mock_table = MagicMock()
        mock_ddb.return_value.Table.return_value = mock_table

        handler_module._save_checkpoint("default", "file2.log")
        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args[1]["Item"]
        assert item["source"] == "vpc_flow:default"
        assert item["last_processed_key"] == "file2.log"


# ===========================================================================
# List unprocessed files
# ===========================================================================

class TestListUnprocessedFiles:
    """_list_unprocessed_files tests."""

    @patch.object(handler_module, "_get_s3")
    def test_lists_files(self, mock_get_s3):
        mock_s3 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "prefix/file1.log"},
                    {"Key": "prefix/file2.log"},
                    {"Key": "prefix/file3.log"},
                ]
            }
        ]
        mock_s3.get_paginator.return_value = paginator
        mock_get_s3.return_value = mock_s3

        files = handler_module._list_unprocessed_files("bucket", "prefix/", None, 10)
        assert len(files) == 3
        assert files == sorted(files)

    @patch.object(handler_module, "_get_s3")
    def test_respects_max_files(self, mock_get_s3):
        mock_s3 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": f"prefix/file{i}.log"} for i in range(20)
                ]
            }
        ]
        mock_s3.get_paginator.return_value = paginator
        mock_get_s3.return_value = mock_s3

        files = handler_module._list_unprocessed_files("bucket", "prefix/", None, 5)
        assert len(files) == 5

    @patch.object(handler_module, "_get_s3")
    def test_skips_directories(self, mock_get_s3):
        mock_s3 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "prefix/"},
                    {"Key": "prefix/subdir/"},
                    {"Key": "prefix/file1.log"},
                ]
            }
        ]
        mock_s3.get_paginator.return_value = paginator
        mock_get_s3.return_value = mock_s3

        files = handler_module._list_unprocessed_files("bucket", "prefix/", None, 10)
        assert len(files) == 1
        assert files[0] == "prefix/file1.log"

    @patch.object(handler_module, "_get_s3")
    def test_uses_start_after(self, mock_get_s3):
        mock_s3 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Contents": []}]
        mock_s3.get_paginator.return_value = paginator
        mock_get_s3.return_value = mock_s3

        handler_module._list_unprocessed_files("bucket", "prefix/", "prefix/last.log", 10)
        call_kwargs = paginator.paginate.call_args[1]
        assert call_kwargs["StartAfter"] == "prefix/last.log"
