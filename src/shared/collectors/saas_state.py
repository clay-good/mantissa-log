"""
Watermark store for SaaS collectors.

Each (source, tenant, feed) tuple has one watermark describing how far the
collector has read. The watermark is the contract that lets the collector
restart safely after a crash, a redeploy, or a clock skew. It also lets
backfill mode know where to stop.

Layout in the lake:
    {prefix}/_state/collectors/{source}/{tenant_id}/{feed}/watermark.json

Watermark shape:
    {
      "last_event_time": "2026-05-09T14:23:11Z",
      "last_event_id":   "9af1...",
      "updated_at":      "2026-05-09T14:24:02Z"
    }

Two backends shipped:
- LocalFile for dev/tests
- S3 for production AWS deployments

GCS and Azure Blob backends will follow the same interface and are added in
their own module per cloud to avoid forcing every deployment to install all
three SDKs.
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Watermark:
    last_event_time: datetime
    last_event_id: Optional[str] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "last_event_time": _iso(self.last_event_time),
            "last_event_id": self.last_event_id,
            "updated_at": _iso(self.updated_at) if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Watermark":
        return cls(
            last_event_time=_parse_iso(data["last_event_time"]),
            last_event_id=data.get("last_event_id"),
            updated_at=_parse_iso(data["updated_at"]) if data.get("updated_at") else None,
        )


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def watermark_key(source: str, tenant_id: str, feed: str) -> str:
    """Return the canonical relative key for a watermark file."""
    safe_tenant = tenant_id.replace("/", "_")
    return f"_state/collectors/{source}/{safe_tenant}/{feed}/watermark.json"


class WatermarkStore(ABC):
    @abstractmethod
    def get(self, source: str, tenant_id: str, feed: str) -> Optional[Watermark]:
        """Return the stored watermark, or None if not present."""

    @abstractmethod
    def put(self, source: str, tenant_id: str, feed: str, watermark: Watermark) -> None:
        """Atomically replace the stored watermark."""


class LocalFileWatermarkStore(WatermarkStore):
    """File-backed store. Writes are atomic via os.replace."""

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)

    def _path(self, source: str, tenant_id: str, feed: str) -> Path:
        return self.root / watermark_key(source, tenant_id, feed)

    def get(self, source: str, tenant_id: str, feed: str) -> Optional[Watermark]:
        path = self._path(source, tenant_id, feed)
        if not path.exists():
            return None
        return Watermark.from_dict(json.loads(path.read_text()))

    def put(self, source: str, tenant_id: str, feed: str, watermark: Watermark) -> None:
        path = self._path(source, tenant_id, feed)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        wm = Watermark(
            last_event_time=watermark.last_event_time,
            last_event_id=watermark.last_event_id,
            updated_at=watermark.updated_at or datetime.now(timezone.utc),
        )
        tmp.write_text(json.dumps(wm.to_dict(), indent=2))
        os.replace(tmp, path)


class S3WatermarkStore(WatermarkStore):
    """S3-backed store. Object writes are inherently atomic in S3.

    ``prefix`` is the in-bucket prefix, e.g. ``mantissa/`` for
    ``s3://my-bucket/mantissa/_state/collectors/...``. Empty string means the
    bucket root.
    """

    def __init__(self, bucket: str, prefix: str = "", s3_client=None):
        self.bucket = bucket
        self.prefix = prefix.lstrip("/")
        if self.prefix and not self.prefix.endswith("/"):
            self.prefix += "/"
        if s3_client is None:
            import boto3  # local import keeps boto3 optional for non-AWS users
            s3_client = boto3.client("s3")
        self.s3 = s3_client

    def _key(self, source: str, tenant_id: str, feed: str) -> str:
        return self.prefix + watermark_key(source, tenant_id, feed)

    def get(self, source: str, tenant_id: str, feed: str) -> Optional[Watermark]:
        from botocore.exceptions import ClientError
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key=self._key(source, tenant_id, feed))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None
            raise
        return Watermark.from_dict(json.loads(obj["Body"].read()))

    def put(self, source: str, tenant_id: str, feed: str, watermark: Watermark) -> None:
        wm = Watermark(
            last_event_time=watermark.last_event_time,
            last_event_id=watermark.last_event_id,
            updated_at=watermark.updated_at or datetime.now(timezone.utc),
        )
        self.s3.put_object(
            Bucket=self.bucket,
            Key=self._key(source, tenant_id, feed),
            Body=json.dumps(wm.to_dict(), indent=2).encode("utf-8"),
            ContentType="application/json",
        )
