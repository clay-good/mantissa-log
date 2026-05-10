"""
Raw-event lake writer for SaaS collectors.

Per spec, each collector writes the raw, untransformed events to the lake at:

    {prefix}/raw/source={source}/dt={YYYY-MM-DD}/hh={HH}/tenant={tenant}/feed={feed}/{batch_id}.jsonl.gz

Raw is preserved separately from the parsed Parquet partition (which is
produced by the existing parser pipeline) so that any future schema change
can re-parse the original record without re-fetching from the upstream API.

Format is gzipped JSON-Lines: one event per line. Chosen because it is
streaming-friendly, append-friendly across batches (each batch is a separate
file), and trivially readable by every analytics tool.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)


def raw_partition_key(
    source: str,
    tenant_id: str,
    feed: str,
    when: datetime,
    batch_id: str | None = None,
) -> str:
    """Return the canonical relative key for a raw batch file."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    when = when.astimezone(timezone.utc)
    safe_tenant = tenant_id.replace("/", "_")
    bid = batch_id or uuid.uuid4().hex
    return (
        f"raw/source={source}/dt={when.strftime('%Y-%m-%d')}/hh={when.strftime('%H')}/"
        f"tenant={safe_tenant}/feed={feed}/{bid}.jsonl.gz"
    )


def _serialize(events: Iterable[dict]) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        for event in events:
            gz.write(json.dumps(event, separators=(",", ":"), default=str).encode("utf-8"))
            gz.write(b"\n")
    return buf.getvalue()


class RawLakeWriter(ABC):
    @abstractmethod
    def write_batch(
        self,
        source: str,
        tenant_id: str,
        feed: str,
        events: Iterable[dict],
        when: datetime | None = None,
        batch_id: str | None = None,
    ) -> str:
        """Write a batch of raw events. Returns the storage key written."""


class LocalFileRawLakeWriter(RawLakeWriter):
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)

    def write_batch(self, source, tenant_id, feed, events, when=None, batch_id=None):
        when = when or datetime.now(timezone.utc)
        key = raw_partition_key(source, tenant_id, feed, when, batch_id)
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_serialize(events))
        return key


class S3RawLakeWriter(RawLakeWriter):
    def __init__(self, bucket: str, prefix: str = "", s3_client=None):
        self.bucket = bucket
        self.prefix = prefix.lstrip("/")
        if self.prefix and not self.prefix.endswith("/"):
            self.prefix += "/"
        if s3_client is None:
            import boto3
            s3_client = boto3.client("s3")
        self.s3 = s3_client

    def write_batch(self, source, tenant_id, feed, events, when=None, batch_id=None):
        when = when or datetime.now(timezone.utc)
        rel = raw_partition_key(source, tenant_id, feed, when, batch_id)
        key = self.prefix + rel
        body = _serialize(events)
        self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=body,
            ContentType="application/x-ndjson",
            ContentEncoding="gzip",
        )
        return key
