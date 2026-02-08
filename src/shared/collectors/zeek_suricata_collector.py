"""
Zeek / Suricata On-Prem Log Collector

Handles local file-based ingestion for on-prem deployments where Zeek or
Suricata writes JSON log files to a directory.

The collector:
  1. Polls a configurable directory for new/modified Zeek/Suricata JSON files.
  2. Tracks the last read position per file for incremental reading.
  3. Auto-detects Zeek vs Suricata format from JSON structure.
  4. Parses using the appropriate parser (ZeekParser / SuricataParser).
  5. Writes normalised events to local storage or uploads to cloud.
  6. Supports log rotation (inode/size change detection).

State File:
  ``{state_dir}/zeek_suricata_state.json``
  Tracks per-file: offset, inode, size, last_modified, format.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from ..parsers.zeek import ZeekParser
    from ..parsers.suricata import SuricataParser
except ImportError:
    from parsers.zeek import ZeekParser
    from parsers.suricata import SuricataParser

logger = logging.getLogger(__name__)

_zeek_parser = ZeekParser()
_suricata_parser = SuricataParser()


# ===========================================================================
# Format detection
# ===========================================================================

def detect_format(raw_event: Dict[str, Any]) -> Optional[str]:
    """Auto-detect whether a JSON event is Zeek or Suricata format.

    Zeek indicators:
      - ``_path`` field (e.g. "conn", "dns", "http")
      - ``id.orig_h`` / ``id.resp_h`` nested fields
      - ``conn_state`` field (conn.log)

    Suricata indicators:
      - ``event_type`` field (e.g. "alert", "flow", "dns")
      - ``alert`` nested object with ``signature_id``

    Args:
        raw_event: A single JSON-parsed log entry.

    Returns:
        ``"zeek"``, ``"suricata"``, or ``None`` if unrecognised.
    """
    if not isinstance(raw_event, dict):
        return None

    # Zeek: _path is the strongest indicator
    if "_path" in raw_event:
        return "zeek"

    # Suricata: event_type is the strongest indicator
    if "event_type" in raw_event:
        return "suricata"

    # Zeek: id.orig_h / id.resp_h structure
    id_field = raw_event.get("id")
    if isinstance(id_field, dict) and ("orig_h" in id_field or "resp_h" in id_field):
        return "zeek"

    # Zeek: conn_state is unique to Zeek conn.log
    if "conn_state" in raw_event:
        return "zeek"

    # Zeek: uid + ts pattern (common in Zeek logs)
    if "uid" in raw_event and "ts" in raw_event:
        return "zeek"

    # Suricata: alert object with signature_id
    alert = raw_event.get("alert")
    if isinstance(alert, dict) and "signature_id" in alert:
        return "suricata"

    # Suricata: flow_id is common in Suricata EVE JSON
    if "flow_id" in raw_event:
        return "suricata"

    return None


def parse_event(
    raw_event: Dict[str, Any],
    format_hint: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Parse a single event using the appropriate parser.

    Args:
        raw_event: Raw JSON event dict.
        format_hint: ``"zeek"`` or ``"suricata"`` to skip detection.

    Returns:
        Normalised event dict, or ``None`` if parsing fails.
    """
    fmt = format_hint or detect_format(raw_event)
    if fmt is None:
        return None

    try:
        if fmt == "zeek":
            if _zeek_parser.validate(raw_event):
                return _zeek_parser.parse(raw_event)
        elif fmt == "suricata":
            if _suricata_parser.validate(raw_event):
                return _suricata_parser.parse(raw_event)
    except Exception:
        logger.debug("Failed to parse %s event: %s", fmt, str(raw_event)[:200])

    return None


# ===========================================================================
# File state tracking
# ===========================================================================

class FileState:
    """Tracks per-file reading state for incremental ingestion."""

    def __init__(
        self,
        path: str,
        offset: int = 0,
        inode: int = 0,
        size: int = 0,
        last_modified: float = 0.0,
        fmt: Optional[str] = None,
    ):
        self.path = path
        self.offset = offset
        self.inode = inode
        self.size = size
        self.last_modified = last_modified
        self.fmt = fmt

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "offset": self.offset,
            "inode": self.inode,
            "size": self.size,
            "last_modified": self.last_modified,
            "format": self.fmt,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileState":
        return cls(
            path=data["path"],
            offset=data.get("offset", 0),
            inode=data.get("inode", 0),
            size=data.get("size", 0),
            last_modified=data.get("last_modified", 0.0),
            fmt=data.get("format"),
        )


def _load_state(state_file: str) -> Dict[str, FileState]:
    """Load file tracking state from disk.

    Args:
        state_file: Path to the JSON state file.

    Returns:
        Dict mapping file paths to FileState objects.
    """
    if not os.path.exists(state_file):
        return {}

    try:
        with open(state_file, "r") as f:
            data = json.load(f)
        return {k: FileState.from_dict(v) for k, v in data.items()}
    except Exception:
        logger.warning("Failed to load state from %s", state_file)
        return {}


def _save_state(state_file: str, states: Dict[str, FileState]) -> None:
    """Persist file tracking state to disk.

    Args:
        state_file: Path to the JSON state file.
        states: Dict mapping file paths to FileState objects.
    """
    try:
        data = {k: v.to_dict() for k, v in states.items()}
        state_dir = os.path.dirname(state_file)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)
        with open(state_file, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        logger.exception("Failed to save state to %s", state_file)


# ===========================================================================
# File reading
# ===========================================================================

def _get_file_info(path: str) -> Tuple[int, int, float]:
    """Get inode, size, and mtime for a file.

    Returns:
        (inode, size, mtime) tuple.
    """
    try:
        stat = os.stat(path)
        return stat.st_ino, stat.st_size, stat.st_mtime
    except OSError:
        return 0, 0, 0.0


def _detect_rotation(state: FileState, inode: int, size: int) -> bool:
    """Detect if a file has been rotated (new inode or shrunk).

    Args:
        state: Previous file state.
        inode: Current inode.
        size: Current file size.

    Returns:
        ``True`` if the file appears to have been rotated.
    """
    if state.inode != 0 and state.inode != inode:
        return True
    if size < state.offset:
        return True
    return False


def _read_new_lines(
    file_path: str,
    offset: int,
) -> Tuple[List[str], int]:
    """Read new lines from a file starting at the given byte offset.

    Args:
        file_path: Path to the log file.
        offset: Byte offset to start reading from.

    Returns:
        (list_of_lines, new_offset) tuple.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            lines = f.readlines()
            new_offset = f.tell()
        return [line.strip() for line in lines if line.strip()], new_offset
    except Exception:
        logger.debug("Failed to read %s at offset %d", file_path, offset)
        return [], offset


def _parse_lines(
    lines: List[str],
    format_hint: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse JSON lines into normalised events.

    Args:
        lines: Raw text lines from a log file.
        format_hint: Optional format to skip detection.

    Returns:
        (parsed_events, detected_format) tuple.
    """
    events: List[Dict[str, Any]] = []
    detected_fmt = format_hint

    for line in lines:
        try:
            raw = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue

        if not isinstance(raw, dict):
            continue

        # Auto-detect format from first valid event
        if detected_fmt is None:
            detected_fmt = detect_format(raw)

        result = parse_event(raw, format_hint=detected_fmt)
        if result is not None:
            events.append(result)

    return events, detected_fmt


# ===========================================================================
# Output writers
# ===========================================================================

def write_local(
    events: List[Dict[str, Any]],
    output_dir: str,
    source_format: str,
    timestamp: Optional[datetime] = None,
) -> Optional[str]:
    """Write normalised events to a local NDJSON file.

    Args:
        events: List of normalised event dicts.
        output_dir: Directory to write output files.
        source_format: ``"zeek"`` or ``"suricata"``.
        timestamp: Partition timestamp (default: now).

    Returns:
        Path to the output file, or ``None`` on failure.
    """
    if not events:
        return None

    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    year = timestamp.strftime("%Y")
    month = timestamp.strftime("%m")
    day = timestamp.strftime("%d")
    hour = timestamp.strftime("%H")

    partition_dir = os.path.join(
        output_dir, source_format, "raw", year, month, day, hour
    )
    os.makedirs(partition_dir, exist_ok=True)

    filename = f"{source_format}_{timestamp.strftime('%M%S')}_{int(time.time()) % 10000:04d}.json"
    output_path = os.path.join(partition_dir, filename)

    try:
        content = "\n".join(json.dumps(e) for e in events)
        with open(output_path, "w") as f:
            f.write(content)
        logger.info("Wrote %d events to %s", len(events), output_path)
        return output_path
    except Exception:
        logger.exception("Failed to write to %s", output_path)
        return None


# ===========================================================================
# Main collector
# ===========================================================================

class ZeekSuricataCollector:
    """On-prem Zeek/Suricata log file collector.

    Polls a watch directory for new/modified log files, reads incrementally,
    parses using the appropriate parser, and writes normalised events to
    a configurable output.

    Args:
        watch_dirs: List of directories to watch for log files.
        output_dir: Directory for normalised output (local mode).
        state_dir: Directory for state tracking files.
        file_patterns: Glob patterns for log files (default: ``["*.json", "*.log"]``).
        upload_fn: Optional callback ``(events, format) -> path`` for cloud upload.
        batch_size: Maximum events per output file.
    """

    def __init__(
        self,
        watch_dirs: List[str],
        output_dir: str = "",
        state_dir: str = "",
        file_patterns: Optional[List[str]] = None,
        upload_fn: Optional[Callable] = None,
        batch_size: int = 10000,
    ):
        self.watch_dirs = watch_dirs
        self.output_dir = output_dir
        self.state_dir = state_dir or output_dir
        self.file_patterns = file_patterns or ["*.json", "*.log"]
        self.upload_fn = upload_fn
        self.batch_size = batch_size

        self._state_file = os.path.join(
            self.state_dir, "zeek_suricata_state.json"
        )
        self._states: Dict[str, FileState] = {}

    def collect(self) -> Dict[str, Any]:
        """Run one collection cycle.

        Scans watch directories, reads new data from modified files,
        parses events, and writes output.

        Returns:
            Summary dict with collection statistics.
        """
        self._states = _load_state(self._state_file)

        files = self._discover_files()
        total_events = 0
        total_files_processed = 0
        output_paths: List[str] = []
        formats_seen: Dict[str, int] = {}

        for file_path in files:
            events, fmt = self._process_file(file_path)
            if not events:
                continue

            total_events += len(events)
            total_files_processed += 1

            if fmt:
                formats_seen[fmt] = formats_seen.get(fmt, 0) + len(events)

            # Write output in batches
            paths = self._write_events(events, fmt or "unknown")
            output_paths.extend(paths)

        _save_state(self._state_file, self._states)

        return {
            "status": "success",
            "files_scanned": len(files),
            "files_processed": total_files_processed,
            "total_events": total_events,
            "formats": formats_seen,
            "output_paths": output_paths,
        }

    def _discover_files(self) -> List[str]:
        """Discover log files in watch directories.

        Returns:
            List of file paths matching the configured patterns.
        """
        files: List[str] = []

        for watch_dir in self.watch_dirs:
            if not os.path.isdir(watch_dir):
                logger.warning("Watch directory not found: %s", watch_dir)
                continue

            watch_path = Path(watch_dir)
            for pattern in self.file_patterns:
                for match in watch_path.glob(pattern):
                    if match.is_file():
                        files.append(str(match))

        return sorted(set(files))

    def _process_file(
        self, file_path: str
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Process a single log file incrementally.

        Args:
            file_path: Path to the log file.

        Returns:
            (parsed_events, detected_format) tuple.
        """
        inode, size, mtime = _get_file_info(file_path)
        if size == 0:
            return [], None

        state = self._states.get(file_path)

        if state is not None:
            # Check for rotation
            if _detect_rotation(state, inode, size):
                logger.info("Log rotation detected for %s", file_path)
                state = FileState(
                    path=file_path, inode=inode, size=size,
                    last_modified=mtime,
                )

            # No new data
            if mtime <= state.last_modified and size == state.size:
                return [], state.fmt
        else:
            state = FileState(
                path=file_path, inode=inode, size=size,
                last_modified=mtime,
            )

        # Read new lines
        lines, new_offset = _read_new_lines(file_path, state.offset)
        if not lines:
            state.offset = new_offset
            state.inode = inode
            state.size = size
            state.last_modified = mtime
            self._states[file_path] = state
            return [], state.fmt

        # Parse
        events, detected_fmt = _parse_lines(lines, format_hint=state.fmt)

        # Update state
        state.offset = new_offset
        state.inode = inode
        state.size = size
        state.last_modified = mtime
        if detected_fmt:
            state.fmt = detected_fmt
        self._states[file_path] = state

        return events, detected_fmt

    def _write_events(
        self,
        events: List[Dict[str, Any]],
        source_format: str,
    ) -> List[str]:
        """Write events using local writer or upload callback.

        Args:
            events: Normalised events.
            source_format: ``"zeek"`` or ``"suricata"``.

        Returns:
            List of output paths.
        """
        paths: List[str] = []
        now = datetime.now(timezone.utc)

        for i in range(0, len(events), self.batch_size):
            batch = events[i : i + self.batch_size]

            if self.upload_fn:
                path = self.upload_fn(batch, source_format)
            elif self.output_dir:
                path = write_local(batch, self.output_dir, source_format, now)
            else:
                path = None

            if path:
                paths.append(path)

        return paths


# ===========================================================================
# Cloud upload helpers
# ===========================================================================

def parse_uploaded_file(content: bytes) -> Tuple[List[Dict[str, Any]], str]:
    """Parse an uploaded Zeek/Suricata log file.

    Suitable for use by cloud collector handlers that receive file
    uploads via S3/GCS/Blob triggers.

    Args:
        content: Raw file bytes (NDJSON).

    Returns:
        (parsed_events, detected_format) tuple.
        detected_format is ``"zeek"``, ``"suricata"``, or ``"unknown"``.
    """
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return [], "unknown"

    lines = [line.strip() for line in text.strip().split("\n") if line.strip()]
    events, fmt = _parse_lines(lines)

    return events, fmt or "unknown"
