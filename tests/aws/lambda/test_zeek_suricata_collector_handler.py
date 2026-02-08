"""Unit tests for the AWS Zeek/Suricata Log Collector Lambda."""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/aws/lambda")
)
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../../../src/shared")
)

import zeek_suricata_collector_handler as handler_module


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


def _make_s3_event(bucket, key):
    return {
        "Records": [
            {"s3": {"bucket": {"name": bucket}, "object": {"key": key}}}
        ]
    }


# ===========================================================================
# Test: _read_s3_file
# ===========================================================================

class TestReadS3File:
    @patch.object(handler_module, "_get_s3")
    def test_reads_content(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3
        content = json.dumps(_ZEEK_CONN).encode("utf-8")
        mock_s3.get_object.return_value = {
            "Body": MagicMock(read=lambda: content)
        }
        result = handler_module._read_s3_file("bucket", "key.json")
        assert result == content

    @patch.object(handler_module, "_get_s3")
    def test_failure_returns_empty(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3
        mock_s3.get_object.side_effect = Exception("S3 error")
        assert handler_module._read_s3_file("bucket", "key") == b""


# ===========================================================================
# Test: _write_to_data_lake
# ===========================================================================

class TestWriteToDataLake:
    @patch.object(handler_module, "_get_s3")
    def test_writes_ndjson(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        key = handler_module._write_to_data_lake(
            [{"a": 1}], "bucket", "zeek", ts, "part01"
        )
        assert key == "zeek/raw/2025/06/15/10/zeek_part01.json"
        mock_s3.put_object.assert_called_once()

    @patch.object(handler_module, "_get_s3")
    def test_suricata_path(self, mock_get_s3):
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        key = handler_module._write_to_data_lake(
            [{"a": 1}], "bucket", "suricata", ts, "part01"
        )
        assert key.startswith("suricata/raw/")

    def test_empty_events(self):
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert handler_module._write_to_data_lake([], "b", "zeek", ts) is None


# ===========================================================================
# Test: _report_health
# ===========================================================================

class TestReportHealth:
    @patch("src.shared.health.health_state_store.DynamoDBHealthStateStore")
    def test_reports_zeek(self, mock_store_cls):
        os.environ["LOG_SOURCE_HEALTH_TABLE"] = "health-table"
        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        handler_module._report_health(10, "zeek")
        assert (
            mock_store.update_event_count.call_args[1]["source_type"] == "zeek"
        )
        os.environ.pop("LOG_SOURCE_HEALTH_TABLE", None)

    @patch("src.shared.health.health_state_store.DynamoDBHealthStateStore")
    def test_reports_suricata(self, mock_store_cls):
        os.environ["LOG_SOURCE_HEALTH_TABLE"] = "health-table"
        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        handler_module._report_health(5, "suricata")
        assert (
            mock_store.update_event_count.call_args[1]["source_type"]
            == "suricata"
        )
        os.environ.pop("LOG_SOURCE_HEALTH_TABLE", None)


# ===========================================================================
# Test: lambda_handler
# ===========================================================================

class TestLambdaHandler:
    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_is_processed", return_value=False)
    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_read_s3_file")
    def test_processes_zeek_file(
        self, mock_read, mock_batch, mock_health, mock_check, mock_save
    ):
        os.environ["LOGS_BUCKET"] = "test-lake"
        content = (
            json.dumps(_ZEEK_CONN) + "\n" + json.dumps(_ZEEK_CONN)
        ).encode("utf-8")
        mock_read.return_value = content
        mock_batch.return_value = ["key1"]

        event = _make_s3_event("source", "zeek/conn.json")
        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        assert result["total_events"] == 2
        assert result["formats"]["zeek"] == 2
        os.environ.pop("LOGS_BUCKET", None)

    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_is_processed", return_value=False)
    @patch.object(handler_module, "_report_health")
    @patch.object(handler_module, "_batch_and_write")
    @patch.object(handler_module, "_read_s3_file")
    def test_processes_suricata_file(
        self, mock_read, mock_batch, mock_health, mock_check, mock_save
    ):
        os.environ["LOGS_BUCKET"] = "test-lake"
        content = json.dumps(_SURICATA_ALERT).encode("utf-8")
        mock_read.return_value = content
        mock_batch.return_value = ["key1"]

        event = _make_s3_event("source", "suricata/eve.json")
        result = handler_module.lambda_handler(event, None)

        assert result["total_events"] == 1
        assert result["formats"]["suricata"] == 1
        os.environ.pop("LOGS_BUCKET", None)

    @patch.object(handler_module, "_is_processed", return_value=True)
    def test_skips_processed(self, mock_check):
        os.environ["LOGS_BUCKET"] = "test-lake"
        event = _make_s3_event("source", "logs/conn.json")
        result = handler_module.lambda_handler(event, None)
        assert result["total_events"] == 0
        os.environ.pop("LOGS_BUCKET", None)

    def test_no_records(self):
        os.environ["LOGS_BUCKET"] = "test-lake"
        result = handler_module.lambda_handler({}, None)
        assert result["total_events"] == 0
        os.environ.pop("LOGS_BUCKET", None)


# ===========================================================================
# Test: Integration
# ===========================================================================

class TestIntegration:
    @patch.object(handler_module, "_get_s3")
    @patch.object(handler_module, "_save_checkpoint")
    @patch.object(handler_module, "_is_processed", return_value=False)
    @patch.object(handler_module, "_report_health")
    def test_full_pipeline(
        self, mock_health, mock_check, mock_save, mock_get_s3
    ):
        os.environ["LOGS_BUCKET"] = "test-lake"
        mock_s3 = MagicMock()
        mock_get_s3.return_value = mock_s3

        content = "\n".join(
            [json.dumps(_ZEEK_CONN), json.dumps(_ZEEK_CONN)]
        ).encode("utf-8")
        mock_s3.get_object.return_value = {
            "Body": MagicMock(read=lambda: content)
        }

        event = _make_s3_event("source", "zeek/conn.json")
        result = handler_module.lambda_handler(event, None)

        assert result["total_events"] == 2
        assert result["files_written"] == 1
        mock_s3.put_object.assert_called_once()

        body = mock_s3.put_object.call_args[1]["Body"].decode("utf-8")
        lines = body.strip().split("\n")
        assert len(lines) == 2

        s3_key = mock_s3.put_object.call_args[1]["Key"]
        assert s3_key.startswith("zeek/raw/")

        os.environ.pop("LOGS_BUCKET", None)
