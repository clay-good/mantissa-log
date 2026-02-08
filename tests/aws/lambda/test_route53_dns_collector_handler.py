"""Unit tests for the AWS Route 53 DNS Query Log Collector handler."""

import base64
import gzip
import json
import os
import sys
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

import pytest

# Ensure the Lambda handler directory is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/aws/lambda"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/shared"))

import route53_dns_collector_handler as handler_module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_globals():
    """Reset global state between tests."""
    handler_module._s3_client = None
    handler_module._logs_client = None
    handler_module._dynamodb_resource = None
    yield


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_SAMPLE_DNS_EVENT = {
    "version": "1.100000",
    "account_id": "123456789012",
    "region": "us-east-1",
    "vpc_id": "vpc-abc123",
    "query_timestamp": "2025-06-15T10:00:00Z",
    "query_name": "api.example.com.",
    "query_type": "A",
    "query_class": "IN",
    "rcode": "NOERROR",
    "answers": [
        {"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"}
    ],
    "srcaddr": "10.0.0.4",
    "srcport": "54321",
    "transport": "UDP",
    "srcids": {"instance": "i-0abc123", "resolver_endpoint": "rslvr-in-abc123"},
    "firewall_rule_group_id": "",
    "firewall_rule_action": "",
    "firewall_domain_list_id": "",
}

_SAMPLE_DNS_EVENT_NXDOMAIN = {
    "version": "1.100000",
    "account_id": "123456789012",
    "region": "us-east-1",
    "vpc_id": "vpc-abc123",
    "query_timestamp": "2025-06-15T10:00:01Z",
    "query_name": "nonexistent.example.com.",
    "query_type": "A",
    "query_class": "IN",
    "rcode": "NXDOMAIN",
    "answers": [],
    "srcaddr": "10.0.0.5",
    "srcport": "12345",
    "transport": "UDP",
    "srcids": {"instance": "i-0abc456"},
    "firewall_rule_group_id": "",
    "firewall_rule_action": "",
    "firewall_domain_list_id": "",
}

_SAMPLE_DNS_EVENT_AAAA = {
    "version": "1.100000",
    "account_id": "123456789012",
    "region": "us-east-1",
    "vpc_id": "vpc-abc123",
    "query_timestamp": "2025-06-15T10:00:02Z",
    "query_name": "ipv6.example.com.",
    "query_type": "AAAA",
    "query_class": "IN",
    "rcode": "NOERROR",
    "answers": [
        {"Rdata": "2001:db8::1", "Type": "AAAA", "Class": "IN"}
    ],
    "srcaddr": "10.0.0.6",
    "srcport": "65432",
    "transport": "UDP",
    "srcids": {"instance": "i-0abc789"},
}


def _make_cloudwatch_event(events: list) -> dict:
    """Create a CloudWatch Logs subscription filter event."""
    log_events = [
        {
            "id": str(i),
            "timestamp": 1718445600000 + i * 1000,
            "message": json.dumps(e),
        }
        for i, e in enumerate(events)
    ]
    payload = {
        "messageType": "DATA_MESSAGE",
        "owner": "123456789012",
        "logGroup": "/aws/route53/hosted-zone-1",
        "logStream": "vpc-abc123/dns",
        "logEvents": log_events,
    }
    compressed = gzip.compress(json.dumps(payload).encode("utf-8"))
    encoded = base64.b64encode(compressed).decode("utf-8")
    return {"awslogs": {"data": encoded}}


# ===========================================================================
# Test: _decode_cloudwatch_logs
# ===========================================================================

class TestDecodeCloudWatchLogs:
    """Tests for CloudWatch Logs event decoding."""

    def test_decode_single_event(self):
        cw_event = _make_cloudwatch_event([_SAMPLE_DNS_EVENT])
        result = handler_module._decode_cloudwatch_logs(cw_event)
        assert len(result) == 1
        assert result[0]["query_name"] == "api.example.com."

    def test_decode_multiple_events(self):
        cw_event = _make_cloudwatch_event([
            _SAMPLE_DNS_EVENT,
            _SAMPLE_DNS_EVENT_NXDOMAIN,
            _SAMPLE_DNS_EVENT_AAAA,
        ])
        result = handler_module._decode_cloudwatch_logs(cw_event)
        assert len(result) == 3

    def test_empty_data(self):
        result = handler_module._decode_cloudwatch_logs({"awslogs": {"data": ""}})
        assert result == []

    def test_missing_awslogs(self):
        result = handler_module._decode_cloudwatch_logs({})
        assert result == []

    def test_non_json_messages_skipped(self):
        """Non-JSON messages in log events are skipped."""
        payload = {
            "messageType": "DATA_MESSAGE",
            "logEvents": [
                {"message": json.dumps(_SAMPLE_DNS_EVENT)},
                {"message": "this is not json"},
                {"message": json.dumps(_SAMPLE_DNS_EVENT_NXDOMAIN)},
            ],
        }
        compressed = gzip.compress(json.dumps(payload).encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")
        event = {"awslogs": {"data": encoded}}
        result = handler_module._decode_cloudwatch_logs(event)
        assert len(result) == 2

    def test_empty_messages_skipped(self):
        payload = {
            "messageType": "DATA_MESSAGE",
            "logEvents": [
                {"message": ""},
                {"message": "  "},
                {"message": json.dumps(_SAMPLE_DNS_EVENT)},
            ],
        }
        compressed = gzip.compress(json.dumps(payload).encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")
        event = {"awslogs": {"data": encoded}}
        result = handler_module._decode_cloudwatch_logs(event)
        assert len(result) == 1


# ===========================================================================
# Test: _poll_log_group
# ===========================================================================

class TestPollLogGroup:
    """Tests for CloudWatch Logs polling."""

    @patch.object(handler_module, "_get_logs")
    def test_polls_single_page(self, mock_get_logs):
        mock_client = MagicMock()
        mock_get_logs.return_value = mock_client
        mock_client.filter_log_events.return_value = {
            "events": [
                {"message": json.dumps(_SAMPLE_DNS_EVENT)},
                {"message": json.dumps(_SAMPLE_DNS_EVENT_NXDOMAIN)},
            ],
        }

        result = handler_module._poll_log_group("/aws/route53/zone1", 1000, 2000)
        assert len(result) == 2
        mock_client.filter_log_events.assert_called_once()
        call_kwargs = mock_client.filter_log_events.call_args[1]
        assert call_kwargs["logGroupName"] == "/aws/route53/zone1"
        assert call_kwargs["startTime"] == 1000
        assert call_kwargs["endTime"] == 2000

    @patch.object(handler_module, "_get_logs")
    def test_polls_multiple_pages(self, mock_get_logs):
        mock_client = MagicMock()
        mock_get_logs.return_value = mock_client
        mock_client.filter_log_events.side_effect = [
            {
                "events": [{"message": json.dumps(_SAMPLE_DNS_EVENT)}],
                "nextToken": "token1",
            },
            {
                "events": [{"message": json.dumps(_SAMPLE_DNS_EVENT_NXDOMAIN)}],
            },
        ]

        result = handler_module._poll_log_group("/aws/route53/zone1", 1000, 2000)
        assert len(result) == 2
        assert mock_client.filter_log_events.call_count == 2

    @patch.object(handler_module, "_get_logs")
    def test_empty_log_group(self, mock_get_logs):
        mock_client = MagicMock()
        mock_get_logs.return_value = mock_client
        mock_client.filter_log_events.return_value = {"events": []}

        result = handler_module._poll_log_group("/aws/route53/zone1", 1000, 2000)
        assert result == []

    @patch.object(handler_module, "_get_logs")
    def test_exception_returns_empty(self, mock_get_logs):
        mock_client = MagicMock()
        mock_get_logs.return_value = mock_client
        mock_client.filter_log_events.side_effect = Exception("CloudWatch error")

        result = handler_module._poll_log_group("/aws/route53/zone1", 1000, 2000)
        assert result == []

    @patch.object(handler_module, "_get_logs")
    def test_non_json_messages_skipped(self, mock_get_logs):
        mock_client = MagicMock()
        mock_get_logs.return_value = mock_client
        mock_client.filter_log_events.return_value = {
            "events": [
                {"message": json.dumps(_SAMPLE_DNS_EVENT)},
                {"message": "plain text not json"},
                {"message": ""},
            ],
        }

        result = handler_module._poll_log_group("/aws/route53/zone1", 1000, 2000)
        assert len(result) == 1


# ===========================================================================
# Test: _parse_dns_events
# ===========================================================================

class TestParseDNSEvents:
    """Tests for DNS event parsing."""

    def test_parse_valid_event(self):
        result = handler_module._parse_dns_events([_SAMPLE_DNS_EVENT])
        assert len(result) == 1
        event = result[0]
        assert event["service"] == "route53"
        assert event["source_ip"] == "10.0.0.4"
        assert event["result"] == "success"
        assert event["metadata"]["query_name"] == "api.example.com"

    def test_parse_nxdomain(self):
        result = handler_module._parse_dns_events([_SAMPLE_DNS_EVENT_NXDOMAIN])
        assert len(result) == 1
        event = result[0]
        assert event["result"] == "failure"
        assert event["metadata"]["is_nxdomain"] is True
        assert event["metadata"]["response_code"] == "NXDOMAIN"

    def test_parse_multiple_events(self):
        result = handler_module._parse_dns_events([
            _SAMPLE_DNS_EVENT,
            _SAMPLE_DNS_EVENT_NXDOMAIN,
            _SAMPLE_DNS_EVENT_AAAA,
        ])
        assert len(result) == 3

    def test_invalid_events_skipped(self):
        result = handler_module._parse_dns_events([
            _SAMPLE_DNS_EVENT,
            {"not": "a dns event"},  # Missing query_name
            _SAMPLE_DNS_EVENT_NXDOMAIN,
        ])
        assert len(result) == 2

    def test_empty_input(self):
        result = handler_module._parse_dns_events([])
        assert result == []

    def test_parsed_event_has_required_fields(self):
        result = handler_module._parse_dns_events([_SAMPLE_DNS_EVENT])
        event = result[0]
        assert "timestamp" in event
        assert "source_ip" in event
        assert "destination_ip" in event
        assert "action" in event
        assert "result" in event
        assert "service" in event
        assert "metadata" in event
        assert "raw_event" in event

    def test_parsed_metadata_has_dns_tags(self):
        result = handler_module._parse_dns_events([_SAMPLE_DNS_EVENT])
        meta = result[0]["metadata"]
        assert "dns" in meta["tags"]

    def test_resolved_ips_extracted(self):
        result = handler_module._parse_dns_events([_SAMPLE_DNS_EVENT])
        meta = result[0]["metadata"]
        assert "93.184.216.34" in meta["resolved_ips"]

    def test_subdomain_analysis(self):
        result = handler_module._parse_dns_events([_SAMPLE_DNS_EVENT])
        meta = result[0]["metadata"]
        assert meta["subdomain_count"] == 3  # api, example, com
        assert isinstance(meta["subdomain_entropy"], float)


# ===========================================================================
# Test: _write_to_data_lake
# ===========================================================================

class TestWriteToDataLake:
    """Tests for data lake writes."""

    @patch.object(handler_module, "_get_s3")
    def test_writes_ndjson(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        events = handler_module._parse_dns_events([_SAMPLE_DNS_EVENT])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

        key = handler_module._write_to_data_lake(events, "my-bucket", ts, "part01")
        assert key == "route53_dns/raw/2025/06/15/10/dns_part01.json"
        mock_s3.put_object.assert_called_once()
        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "my-bucket"
        # Verify NDJSON content
        body = call_kwargs["Body"].decode("utf-8")
        lines = body.strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["service"] == "route53"

    @patch.object(handler_module, "_get_s3")
    def test_empty_events_returns_none(self, mock_get_s3):
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        key = handler_module._write_to_data_lake([], "my-bucket", ts)
        assert key is None
        mock_get_s3.return_value.put_object.assert_not_called()

    @patch.object(handler_module, "_get_s3")
    def test_s3_failure_returns_none(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3
        mock_s3.put_object.side_effect = Exception("S3 error")

        events = handler_module._parse_dns_events([_SAMPLE_DNS_EVENT])
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

        key = handler_module._write_to_data_lake(events, "my-bucket", ts)
        assert key is None

    @patch.object(handler_module, "_get_s3")
    def test_default_partition_id(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        events = handler_module._parse_dns_events([_SAMPLE_DNS_EVENT])
        ts = datetime(2025, 6, 15, 10, 30, 45, tzinfo=timezone.utc)

        key = handler_module._write_to_data_lake(events, "my-bucket", ts)
        assert key == "route53_dns/raw/2025/06/15/10/dns_3045.json"


# ===========================================================================
# Test: _batch_and_write
# ===========================================================================

class TestBatchAndWrite:
    """Tests for batch splitting and writing."""

    @patch.object(handler_module, "_write_to_data_lake")
    def test_single_batch(self, mock_write):
        mock_write.return_value = "key1"
        events = [{"a": 1}, {"a": 2}]
        keys = handler_module._batch_and_write(events, "bucket", 10)
        assert keys == ["key1"]
        mock_write.assert_called_once()

    @patch.object(handler_module, "_write_to_data_lake")
    def test_multiple_batches(self, mock_write):
        mock_write.side_effect = ["key1", "key2", "key3"]
        events = [{"a": i} for i in range(25)]
        keys = handler_module._batch_and_write(events, "bucket", 10)
        assert len(keys) == 3
        assert mock_write.call_count == 3

    @patch.object(handler_module, "_write_to_data_lake")
    def test_partition_prefix(self, mock_write):
        mock_write.return_value = "key1"
        events = [{"a": 1}]
        handler_module._batch_and_write(events, "bucket", 10, partition_prefix="sub_")
        call_args = mock_write.call_args
        # partition_id should start with prefix
        partition_id = call_args[0][3] if len(call_args[0]) > 3 else call_args[1].get("partition_id", "")
        assert partition_id.startswith("sub_")


# ===========================================================================
# Test: _report_health
# ===========================================================================

class TestReportHealth:
    """Tests for health reporting."""

    @patch.dict(os.environ, {"LOG_SOURCE_HEALTH_TABLE": "health-table", "TENANT_ID": "t1"})
    @patch("src.shared.health.health_state_store.DynamoDBHealthStateStore")
    def test_reports_health(self, mock_store_cls):
        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        handler_module._report_health(42)
        mock_store.update_event_count.assert_called_once()
        call_kwargs = mock_store.update_event_count.call_args[1]
        assert call_kwargs["source_type"] == "route53_dns"
        assert call_kwargs["count_increment"] == 42
        assert call_kwargs["tenant_id"] == "t1"

    @patch.dict(os.environ, {}, clear=True)
    def test_no_health_table(self):
        """No crash when health table not configured."""
        handler_module._report_health(100)  # Should not raise


# ===========================================================================
# Test: Checkpoint management
# ===========================================================================

class TestCheckpoints:
    """Tests for checkpoint get/save."""

    @patch.dict(os.environ, {"CHECKPOINT_TABLE": "checkpoints"})
    @patch.object(handler_module, "_get_dynamodb")
    def test_get_checkpoint(self, mock_ddb):
        mock_table = MagicMock()
        mock_ddb.return_value.Table.return_value = mock_table
        mock_table.get_item.return_value = {
            "Item": {"source": "route53_dns:/aws/route53/z1", "last_poll_timestamp_ms": 1718445600000}
        }
        result = handler_module._get_checkpoint("/aws/route53/z1")
        assert result == 1718445600000
        mock_table.get_item.assert_called_once_with(
            Key={"source": "route53_dns:/aws/route53/z1"}
        )

    @patch.dict(os.environ, {"CHECKPOINT_TABLE": "checkpoints"})
    @patch.object(handler_module, "_get_dynamodb")
    def test_get_checkpoint_no_item(self, mock_ddb):
        mock_table = MagicMock()
        mock_ddb.return_value.Table.return_value = mock_table
        mock_table.get_item.return_value = {}
        result = handler_module._get_checkpoint("/aws/route53/z1")
        assert result is None

    @patch.dict(os.environ, {}, clear=True)
    def test_get_checkpoint_no_table(self):
        result = handler_module._get_checkpoint("/aws/route53/z1")
        assert result is None

    @patch.dict(os.environ, {"CHECKPOINT_TABLE": "checkpoints"})
    @patch.object(handler_module, "_get_dynamodb")
    def test_save_checkpoint(self, mock_ddb):
        mock_table = MagicMock()
        mock_ddb.return_value.Table.return_value = mock_table
        handler_module._save_checkpoint("/aws/route53/z1", 1718445600000)
        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args[1]["Item"]
        assert item["source"] == "route53_dns:/aws/route53/z1"
        assert item["last_poll_timestamp_ms"] == 1718445600000

    @patch.dict(os.environ, {}, clear=True)
    def test_save_checkpoint_no_table(self):
        handler_module._save_checkpoint("/aws/route53/z1", 1718445600000)  # No crash

    @patch.dict(os.environ, {"CHECKPOINT_TABLE": "checkpoints"})
    @patch.object(handler_module, "_get_dynamodb")
    def test_get_checkpoint_exception(self, mock_ddb):
        mock_ddb.return_value.Table.side_effect = Exception("DDB error")
        result = handler_module._get_checkpoint("/aws/route53/z1")
        assert result is None


# ===========================================================================
# Test: Lambda handler — CloudWatch Subscription mode
# ===========================================================================

class TestLambdaHandlerCloudWatchSubscription:
    """Tests for the CloudWatch Logs subscription filter mode."""

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    def test_handles_subscription_event(self, mock_batch, mock_health):
        mock_batch.return_value = ["key1"]
        event = _make_cloudwatch_event([_SAMPLE_DNS_EVENT, _SAMPLE_DNS_EVENT_NXDOMAIN])

        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        assert result["mode"] == "cloudwatch_subscription"
        assert result["total_events"] == 2
        mock_batch.assert_called_once()
        mock_health.assert_called_once_with(2)

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    def test_empty_subscription_event(self, mock_batch, mock_health):
        payload = {
            "messageType": "DATA_MESSAGE",
            "logEvents": [],
        }
        compressed = gzip.compress(json.dumps(payload).encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")
        event = {"awslogs": {"data": encoded}}

        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        assert result["total_events"] == 0
        mock_health.assert_not_called()

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    def test_subscription_with_batch_size(self, mock_batch, mock_health):
        """BATCH_SIZE env var is read and passed to _batch_and_write."""
        mock_batch.return_value = ["key1"]
        event = _make_cloudwatch_event([_SAMPLE_DNS_EVENT])

        with patch.dict(os.environ, {"BATCH_SIZE": "500", "LOGS_BUCKET": "my-lake"}):
            handler_module.lambda_handler(event, None)

        call_args = mock_batch.call_args
        assert call_args[0][1] == "my-lake"  # bucket
        assert call_args[0][2] == 500  # batch_size


# ===========================================================================
# Test: Lambda handler — Scheduled poll mode
# ===========================================================================

class TestLambdaHandlerScheduledPoll:
    """Tests for the scheduled poll mode."""

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_get_checkpoint")
    @patch.object(handler_module, "_poll_log_group")
    @patch.dict(os.environ, {
        "LOG_GROUP_NAMES": "/aws/route53/zone1,/aws/route53/zone2",
        "POLL_WINDOW_MINUTES": "15",
        "LOGS_BUCKET": "data-lake",
    })
    def test_polls_multiple_log_groups(self, mock_poll, mock_get_cp, mock_save_cp, mock_batch, mock_health):
        mock_get_cp.return_value = None  # No checkpoint
        mock_poll.side_effect = [
            [_SAMPLE_DNS_EVENT, _SAMPLE_DNS_EVENT_NXDOMAIN],
            [_SAMPLE_DNS_EVENT_AAAA],
        ]
        mock_batch.side_effect = [["key1"], ["key2"]]

        result = handler_module.lambda_handler({}, None)

        assert result["statusCode"] == 200
        assert result["mode"] == "scheduled_poll"
        assert result["log_groups_polled"] == 2
        assert result["total_events"] == 3
        assert mock_poll.call_count == 2
        assert mock_save_cp.call_count == 2
        mock_health.assert_called_once_with(3)

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_get_checkpoint")
    @patch.object(handler_module, "_poll_log_group")
    @patch.dict(os.environ, {
        "LOG_GROUP_NAMES": "/aws/route53/zone1",
        "POLL_WINDOW_MINUTES": "10",
        "LOGS_BUCKET": "data-lake",
    })
    def test_uses_checkpoint_as_start_time(self, mock_poll, mock_get_cp, mock_save_cp, mock_batch, mock_health):
        checkpoint_ms = 1718445000000
        mock_get_cp.return_value = checkpoint_ms
        mock_poll.return_value = [_SAMPLE_DNS_EVENT]
        mock_batch.return_value = ["key1"]

        handler_module.lambda_handler({}, None)

        call_args = mock_poll.call_args
        assert call_args[0][1] == checkpoint_ms  # start_ms from checkpoint

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_get_checkpoint")
    @patch.object(handler_module, "_poll_log_group")
    @patch.dict(os.environ, {
        "LOG_GROUP_NAMES": "/aws/route53/zone1",
        "LOGS_BUCKET": "data-lake",
    })
    def test_empty_log_group_still_saves_checkpoint(self, mock_poll, mock_get_cp, mock_save_cp, mock_health):
        mock_get_cp.return_value = None
        mock_poll.return_value = []  # No events

        result = handler_module.lambda_handler({}, None)

        assert result["total_events"] == 0
        mock_save_cp.assert_called_once()  # Still saves checkpoint
        mock_health.assert_not_called()

    @patch.dict(os.environ, {"LOGS_BUCKET": "data-lake"}, clear=True)
    def test_missing_log_group_names(self):
        result = handler_module.lambda_handler({}, None)
        assert result["statusCode"] == 400
        assert result["error"] == "missing_configuration"

    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_get_checkpoint")
    @patch.object(handler_module, "_poll_log_group")
    @patch.dict(os.environ, {
        "LOG_GROUP_NAMES": "/aws/route53/zone1",
        "LOGS_BUCKET": "data-lake",
    })
    def test_partition_prefix_uses_log_group_name(self, mock_poll, mock_get_cp, mock_save_cp, mock_batch, mock_health):
        mock_get_cp.return_value = None
        mock_poll.return_value = [_SAMPLE_DNS_EVENT]
        mock_batch.return_value = ["key1"]

        handler_module.lambda_handler({}, None)

        call_args = mock_batch.call_args
        prefix = call_args[1].get("partition_prefix", call_args[0][3] if len(call_args[0]) > 3 else "")
        assert prefix.startswith("poll_")


# ===========================================================================
# Test: Lambda handler — Error handling
# ===========================================================================

class TestLambdaHandlerErrorHandling:
    """Tests for top-level error handling."""

    @patch.object(handler_module, "_decode_cloudwatch_logs")
    def test_exception_returns_500(self, mock_decode):
        mock_decode.side_effect = Exception("Unexpected error")
        event = {"awslogs": {"data": "invalid"}}
        result = handler_module.lambda_handler(event, None)
        assert result["statusCode"] == 500
        assert result["error"] == "collection_failed"


# ===========================================================================
# Test: End-to-end integration
# ===========================================================================

class TestIntegration:
    """End-to-end integration tests with mocked AWS services."""

    @patch.object(handler_module, "_get_s3")
    @patch.object(handler_module, "_report_health")
    def test_cloudwatch_subscription_full_pipeline(self, mock_health, mock_get_s3):
        """Full pipeline: CW subscription → parse → write to S3."""
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        event = _make_cloudwatch_event([
            _SAMPLE_DNS_EVENT,
            _SAMPLE_DNS_EVENT_NXDOMAIN,
            _SAMPLE_DNS_EVENT_AAAA,
        ])

        with patch.dict(os.environ, {"LOGS_BUCKET": "test-lake", "BATCH_SIZE": "10000"}):
            result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        assert result["total_events"] == 3
        assert result["files_written"] == 1
        mock_s3.put_object.assert_called_once()

        # Verify NDJSON content
        call_kwargs = mock_s3.put_object.call_args[1]
        body = call_kwargs["Body"].decode("utf-8")
        lines = body.strip().split("\n")
        assert len(lines) == 3

        # Verify each line is valid JSON with expected structure
        for line in lines:
            parsed = json.loads(line)
            assert parsed["service"] == "route53"
            assert "dns" in parsed["metadata"]["tags"]

    @patch.object(handler_module, "_get_s3")
    @patch.object(handler_module, "_get_logs")
    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_get_checkpoint")
    @patch.object(handler_module, "_report_health")
    @patch.dict(os.environ, {
        "LOG_GROUP_NAMES": "/aws/route53/zone1",
        "LOGS_BUCKET": "test-lake",
        "BATCH_SIZE": "2",
    })
    def test_scheduled_poll_full_pipeline(self, mock_health, mock_get_cp, mock_save_cp, mock_get_logs, mock_get_s3):
        """Full pipeline: poll → parse → batch write to S3."""
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        mock_logs = MagicMock()
        mock_get_logs.return_value = mock_logs
        mock_logs.filter_log_events.return_value = {
            "events": [
                {"message": json.dumps(_SAMPLE_DNS_EVENT)},
                {"message": json.dumps(_SAMPLE_DNS_EVENT_NXDOMAIN)},
                {"message": json.dumps(_SAMPLE_DNS_EVENT_AAAA)},
            ],
        }
        mock_get_cp.return_value = None

        result = handler_module.lambda_handler({}, None)

        assert result["statusCode"] == 200
        assert result["total_events"] == 3
        # With batch_size=2: 3 events → 2 batches (2+1)
        assert result["files_written"] == 2
        assert mock_s3.put_object.call_count == 2

    @patch.object(handler_module, "_get_s3")
    @patch.object(handler_module, "_report_health")
    def test_data_lake_path_format(self, mock_health, mock_get_s3):
        """Verify data lake path follows route53_dns/raw/YYYY/MM/DD/HH/ convention."""
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        event = _make_cloudwatch_event([_SAMPLE_DNS_EVENT])

        with patch.dict(os.environ, {"LOGS_BUCKET": "test-lake"}):
            result = handler_module.lambda_handler(event, None)

        assert result["files_written"] == 1
        call_kwargs = mock_s3.put_object.call_args[1]
        key = call_kwargs["Key"]
        assert key.startswith("route53_dns/raw/")
        # Verify partitioning structure: YYYY/MM/DD/HH
        parts = key.split("/")
        assert parts[0] == "route53_dns"
        assert parts[1] == "raw"
        assert len(parts[2]) == 4  # Year
        assert len(parts[3]) == 2  # Month
        assert len(parts[4]) == 2  # Day
        assert len(parts[5]) == 2  # Hour
