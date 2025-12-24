"""Playbook Storage Layer.

This module provides storage implementations for SOAR playbooks with versioning
support. It includes file-based, DynamoDB, and S3 storage backends.

Storage backends:
- FilePlaybookStore: Local filesystem storage with YAML files
- DynamoDBPlaybookStore: AWS DynamoDB storage with GSIs for querying
- S3PlaybookStore: AWS S3 storage with versioning
"""

import json
import logging
import os
import shutil
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

import yaml

from .playbook import (
    Playbook,
    PlaybookTriggerType,
)

logger = logging.getLogger(__name__)


class AlertProtocol(Protocol):
    """Protocol defining the interface for alerts that can trigger playbooks."""
    severity: str
    rule_name: str
    rule_id: str
    tags: List[str]

    def to_dict(self) -> Dict[str, Any]:
        ...


class PlaybookStore(ABC):
    """Abstract base class for playbook storage.

    All storage implementations must implement these methods to provide
    consistent playbook management across different backends.
    """

    @abstractmethod
    def get(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook by ID (current version).

        Args:
            playbook_id: Unique playbook identifier

        Returns:
            Playbook if found, None otherwise
        """
        pass

    @abstractmethod
    def get_version(self, playbook_id: str, version: str) -> Optional[Playbook]:
        """Get a specific version of a playbook.

        Args:
            playbook_id: Unique playbook identifier
            version: Semantic version string (e.g., "1.0.0")

        Returns:
            Playbook if found, None otherwise
        """
        pass

    @abstractmethod
    def list(self, filters: Optional[Dict[str, Any]] = None) -> List[Playbook]:
        """List playbooks with optional filtering.

        Args:
            filters: Optional filters:
                - enabled: bool - Filter by enabled status
                - tags: List[str] - Filter by tags (any match)
                - trigger_type: str - Filter by trigger type
                - author: str - Filter by author

        Returns:
            List of matching playbooks
        """
        pass

    @abstractmethod
    def list_versions(self, playbook_id: str) -> List[str]:
        """List all versions of a playbook.

        Args:
            playbook_id: Unique playbook identifier

        Returns:
            List of version strings, sorted newest first
        """
        pass

    @abstractmethod
    def save(self, playbook: Playbook) -> str:
        """Save a playbook (creates new version if exists).

        Args:
            playbook: Playbook to save

        Returns:
            Playbook ID
        """
        pass

    @abstractmethod
    def delete(self, playbook_id: str) -> bool:
        """Delete a playbook (archive, not hard delete).

        Args:
            playbook_id: Unique playbook identifier

        Returns:
            True if deleted, False if not found
        """
        pass

    def get_by_trigger(self, trigger_type: PlaybookTriggerType) -> List[Playbook]:
        """Get all enabled playbooks with a specific trigger type.

        Args:
            trigger_type: Trigger type to filter by

        Returns:
            List of matching playbooks
        """
        return self.list({
            "enabled": True,
            "trigger_type": trigger_type.value if isinstance(trigger_type, PlaybookTriggerType) else trigger_type
        })

    def get_matching_playbooks(self, alert: AlertProtocol) -> List[Playbook]:
        """Get all playbooks that match an alert.

        Args:
            alert: Alert to match against playbook triggers

        Returns:
            List of playbooks whose triggers match the alert
        """
        alert_playbooks = self.get_by_trigger(PlaybookTriggerType.ALERT)
        matching = []

        for playbook in alert_playbooks:
            if playbook.enabled and playbook.trigger.matches_alert(alert):
                matching.append(playbook)

        return matching


class FilePlaybookStore(PlaybookStore):
    """File-based playbook storage using YAML files.

    Directory structure:
        {base_path}/
            {playbook_id}.yml           # Current version
            versions/
                {playbook_id}/
                    1.0.0.yml
                    1.1.0.yml
            archive/
                {playbook_id}.yml       # Deleted playbooks
    """

    def __init__(self, base_path: str = "rules/playbooks"):
        """Initialize file-based playbook store.

        Args:
            base_path: Base directory for playbook files
        """
        self.base_path = Path(base_path)
        self.versions_path = self.base_path / "versions"
        self.archive_path = self.base_path / "archive"

        # Create directories if they don't exist
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.versions_path.mkdir(exist_ok=True)
        self.archive_path.mkdir(exist_ok=True)

        # Cache for loaded playbooks
        self._cache: Dict[str, Playbook] = {}

    def _get_playbook_path(self, playbook_id: str) -> Path:
        """Get path to current playbook file."""
        return self.base_path / f"{playbook_id}.yml"

    def _get_version_path(self, playbook_id: str, version: str) -> Path:
        """Get path to versioned playbook file."""
        return self.versions_path / playbook_id / f"{version}.yml"

    def _load_playbook(self, file_path: Path) -> Optional[Playbook]:
        """Load a playbook from a YAML file.

        Args:
            file_path: Path to YAML file

        Returns:
            Playbook if valid, None if file not found or invalid
        """
        if not file_path.exists():
            return None

        try:
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)

            if not data:
                return None

            playbook = Playbook.from_dict(data)

            # Validate the playbook
            is_valid, errors = playbook.validate()
            if not is_valid:
                logger.warning(f"Playbook validation errors in {file_path}: {errors}")

            return playbook

        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error loading playbook from {file_path}: {e}")
            return None

    def _save_playbook(self, playbook: Playbook, file_path: Path) -> None:
        """Save a playbook to a YAML file.

        Args:
            playbook: Playbook to save
            file_path: Path to write
        """
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write YAML
        with open(file_path, 'w') as f:
            f.write(playbook.to_yaml())

    def get(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook by ID."""
        # Check cache first
        if playbook_id in self._cache:
            return self._cache[playbook_id]

        playbook = self._load_playbook(self._get_playbook_path(playbook_id))
        if playbook:
            self._cache[playbook_id] = playbook

        return playbook

    def get_version(self, playbook_id: str, version: str) -> Optional[Playbook]:
        """Get a specific version of a playbook."""
        return self._load_playbook(self._get_version_path(playbook_id, version))

    def list(self, filters: Optional[Dict[str, Any]] = None) -> List[Playbook]:
        """List playbooks with optional filtering."""
        playbooks = []
        filters = filters or {}

        # Glob all YAML files in base path (not versions or archive)
        for yaml_file in self.base_path.glob("*.yml"):
            # Skip README and other non-playbook files
            if yaml_file.stem.lower() == "readme":
                continue

            playbook = self._load_playbook(yaml_file)
            if playbook is None:
                continue

            # Apply filters
            if "enabled" in filters:
                if playbook.enabled != filters["enabled"]:
                    continue

            if "tags" in filters:
                filter_tags = filters["tags"]
                if not any(t in playbook.tags for t in filter_tags):
                    continue

            if "trigger_type" in filters:
                filter_trigger = filters["trigger_type"]
                if isinstance(filter_trigger, str):
                    filter_trigger = PlaybookTriggerType(filter_trigger)
                if playbook.trigger.trigger_type != filter_trigger:
                    continue

            if "author" in filters:
                if playbook.author.lower() != filters["author"].lower():
                    continue

            playbooks.append(playbook)

        return playbooks

    def list_versions(self, playbook_id: str) -> List[str]:
        """List all versions of a playbook."""
        versions_dir = self.versions_path / playbook_id

        if not versions_dir.exists():
            return []

        versions = []
        for yaml_file in versions_dir.glob("*.yml"):
            versions.append(yaml_file.stem)

        # Sort by semantic version (newest first)
        def version_key(v: str) -> tuple:
            parts = v.split(".")
            return tuple(int(p) if p.isdigit() else 0 for p in parts)

        versions.sort(key=version_key, reverse=True)
        return versions

    def save(self, playbook: Playbook) -> str:
        """Save a playbook."""
        # Update modified timestamp
        playbook.modified = datetime.utcnow()

        # Get current version path
        current_path = self._get_playbook_path(playbook.id)

        # If exists, backup current version
        if current_path.exists():
            current = self._load_playbook(current_path)
            if current:
                version_path = self._get_version_path(playbook.id, current.version)
                self._save_playbook(current, version_path)

        # Save new version
        self._save_playbook(playbook, current_path)

        # Also save to versions directory
        version_path = self._get_version_path(playbook.id, playbook.version)
        self._save_playbook(playbook, version_path)

        # Update cache
        self._cache[playbook.id] = playbook

        logger.info(f"Saved playbook {playbook.id} version {playbook.version}")
        return playbook.id

    def delete(self, playbook_id: str) -> bool:
        """Delete (archive) a playbook."""
        current_path = self._get_playbook_path(playbook_id)

        if not current_path.exists():
            return False

        # Move to archive
        archive_path = self.archive_path / f"{playbook_id}.yml"
        shutil.move(str(current_path), str(archive_path))

        # Remove from cache
        if playbook_id in self._cache:
            del self._cache[playbook_id]

        logger.info(f"Archived playbook {playbook_id}")
        return True

    def clear_cache(self) -> None:
        """Clear the playbook cache."""
        self._cache.clear()


class DynamoDBPlaybookStore(PlaybookStore):
    """DynamoDB-based playbook storage.

    Tables:
        Primary table (playbooks):
            - PK: playbook_id (S)
            - Attributes: All Playbook fields as JSON
            - GSI: trigger_type-index (trigger_type -> playbook_id)
            - GSI: enabled-index (enabled -> playbook_id)

        Versions table (playbook_versions):
            - PK: playbook_id (S)
            - SK: version (S)
            - Attributes: Full Playbook snapshot
    """

    def __init__(
        self,
        table_name: str = "mantissa_playbooks",
        versions_table_name: str = "mantissa_playbook_versions",
        region: Optional[str] = None,
    ):
        """Initialize DynamoDB playbook store.

        Args:
            table_name: Name of the primary playbooks table
            versions_table_name: Name of the versions table
            region: AWS region (uses default if not specified)
        """
        import boto3

        self.table_name = table_name
        self.versions_table_name = versions_table_name

        session_kwargs = {}
        if region:
            session_kwargs["region_name"] = region

        self.dynamodb = boto3.resource("dynamodb", **session_kwargs)
        self.table = self.dynamodb.Table(table_name)
        self.versions_table = self.dynamodb.Table(versions_table_name)

    def _playbook_to_item(self, playbook: Playbook) -> Dict[str, Any]:
        """Convert Playbook to DynamoDB item."""
        data = playbook.to_dict()

        # Ensure trigger_type is a string for GSI
        data["trigger_type"] = playbook.trigger.trigger_type.value

        # Store enabled as string for GSI
        data["enabled_str"] = "true" if playbook.enabled else "false"

        return data

    def _item_to_playbook(self, item: Dict[str, Any]) -> Playbook:
        """Convert DynamoDB item to Playbook."""
        # Remove GSI helper fields
        item.pop("enabled_str", None)

        return Playbook.from_dict(item)

    def get(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook by ID."""
        try:
            response = self.table.get_item(Key={"playbook_id": playbook_id})
            item = response.get("Item")

            if not item:
                return None

            return self._item_to_playbook(item)

        except Exception as e:
            logger.error(f"Error getting playbook {playbook_id}: {e}")
            return None

    def get_version(self, playbook_id: str, version: str) -> Optional[Playbook]:
        """Get a specific version of a playbook."""
        try:
            response = self.versions_table.get_item(
                Key={
                    "playbook_id": playbook_id,
                    "version": version,
                }
            )
            item = response.get("Item")

            if not item:
                return None

            return self._item_to_playbook(item)

        except Exception as e:
            logger.error(f"Error getting playbook {playbook_id} version {version}: {e}")
            return None

    def list(self, filters: Optional[Dict[str, Any]] = None) -> List[Playbook]:
        """List playbooks with optional filtering."""
        filters = filters or {}
        playbooks = []

        try:
            # Use GSI if filtering by trigger_type
            if "trigger_type" in filters:
                trigger_type = filters["trigger_type"]
                if isinstance(trigger_type, PlaybookTriggerType):
                    trigger_type = trigger_type.value

                response = self.table.query(
                    IndexName="trigger_type-index",
                    KeyConditionExpression="trigger_type = :tt",
                    ExpressionAttributeValues={":tt": trigger_type},
                )
                items = response.get("Items", [])

            # Use GSI if filtering by enabled
            elif "enabled" in filters:
                enabled_str = "true" if filters["enabled"] else "false"
                response = self.table.query(
                    IndexName="enabled-index",
                    KeyConditionExpression="enabled_str = :e",
                    ExpressionAttributeValues={":e": enabled_str},
                )
                items = response.get("Items", [])

            else:
                # Full table scan
                response = self.table.scan()
                items = response.get("Items", [])

                # Handle pagination
                while "LastEvaluatedKey" in response:
                    response = self.table.scan(
                        ExclusiveStartKey=response["LastEvaluatedKey"]
                    )
                    items.extend(response.get("Items", []))

            # Convert to playbooks and apply remaining filters
            for item in items:
                playbook = self._item_to_playbook(item)

                # Apply additional filters
                if "tags" in filters:
                    if not any(t in playbook.tags for t in filters["tags"]):
                        continue

                if "author" in filters:
                    if playbook.author.lower() != filters["author"].lower():
                        continue

                # Re-check enabled if we used a different GSI
                if "enabled" in filters and "trigger_type" in filters:
                    if playbook.enabled != filters["enabled"]:
                        continue

                playbooks.append(playbook)

        except Exception as e:
            logger.error(f"Error listing playbooks: {e}")

        return playbooks

    def list_versions(self, playbook_id: str) -> List[str]:
        """List all versions of a playbook."""
        try:
            response = self.versions_table.query(
                KeyConditionExpression="playbook_id = :pid",
                ExpressionAttributeValues={":pid": playbook_id},
                ProjectionExpression="version",
            )

            versions = [item["version"] for item in response.get("Items", [])]

            # Sort by semantic version (newest first)
            def version_key(v: str) -> tuple:
                parts = v.split(".")
                return tuple(int(p) if p.isdigit() else 0 for p in parts)

            versions.sort(key=version_key, reverse=True)
            return versions

        except Exception as e:
            logger.error(f"Error listing versions for {playbook_id}: {e}")
            return []

    def save(self, playbook: Playbook) -> str:
        """Save a playbook."""
        playbook.modified = datetime.utcnow()
        item = self._playbook_to_item(playbook)

        try:
            # Save to primary table
            self.table.put_item(Item=item)

            # Save to versions table
            version_item = item.copy()
            version_item["version"] = playbook.version
            self.versions_table.put_item(Item=version_item)

            logger.info(f"Saved playbook {playbook.id} version {playbook.version} to DynamoDB")
            return playbook.id

        except Exception as e:
            logger.error(f"Error saving playbook {playbook.id}: {e}")
            raise

    def delete(self, playbook_id: str) -> bool:
        """Delete a playbook."""
        try:
            # Get current playbook for archival logging
            playbook = self.get(playbook_id)
            if not playbook:
                return False

            # Delete from primary table
            self.table.delete_item(Key={"playbook_id": playbook_id})

            # Note: versions are kept for audit trail
            logger.info(f"Deleted playbook {playbook_id} from DynamoDB")
            return True

        except Exception as e:
            logger.error(f"Error deleting playbook {playbook_id}: {e}")
            return False


class S3PlaybookStore(PlaybookStore):
    """S3-based playbook storage.

    Structure:
        {bucket}/{prefix}/
            current/
                {playbook_id}.yml       # Current version
            versions/
                {playbook_id}/
                    1.0.0.yml
                    1.1.0.yml
            archive/
                {playbook_id}.yml       # Deleted playbooks
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "playbooks/",
        region: Optional[str] = None,
    ):
        """Initialize S3 playbook store.

        Args:
            bucket: S3 bucket name
            prefix: Key prefix for playbook files
            region: AWS region (uses default if not specified)
        """
        import boto3

        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"

        session_kwargs = {}
        if region:
            session_kwargs["region_name"] = region

        self.s3 = boto3.client("s3", **session_kwargs)

    def _current_key(self, playbook_id: str) -> str:
        """Get S3 key for current playbook version."""
        return f"{self.prefix}current/{playbook_id}.yml"

    def _version_key(self, playbook_id: str, version: str) -> str:
        """Get S3 key for versioned playbook."""
        return f"{self.prefix}versions/{playbook_id}/{version}.yml"

    def _archive_key(self, playbook_id: str) -> str:
        """Get S3 key for archived playbook."""
        return f"{self.prefix}archive/{playbook_id}.yml"

    def _load_from_s3(self, key: str) -> Optional[Playbook]:
        """Load a playbook from S3."""
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
            content = response["Body"].read().decode("utf-8")
            data = yaml.safe_load(content)

            if not data:
                return None

            return Playbook.from_dict(data)

        except self.s3.exceptions.NoSuchKey:
            return None
        except Exception as e:
            logger.error(f"Error loading playbook from s3://{self.bucket}/{key}: {e}")
            return None

    def _save_to_s3(self, playbook: Playbook, key: str) -> None:
        """Save a playbook to S3."""
        content = playbook.to_yaml()
        self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=content.encode("utf-8"),
            ContentType="application/x-yaml",
        )

    def get(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook by ID."""
        return self._load_from_s3(self._current_key(playbook_id))

    def get_version(self, playbook_id: str, version: str) -> Optional[Playbook]:
        """Get a specific version of a playbook."""
        return self._load_from_s3(self._version_key(playbook_id, version))

    def list(self, filters: Optional[Dict[str, Any]] = None) -> List[Playbook]:
        """List playbooks with optional filtering."""
        filters = filters or {}
        playbooks = []

        try:
            # List all current playbooks
            paginator = self.s3.get_paginator("list_objects_v2")
            prefix = f"{self.prefix}current/"

            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if not key.endswith(".yml"):
                        continue

                    playbook = self._load_from_s3(key)
                    if playbook is None:
                        continue

                    # Apply filters
                    if "enabled" in filters:
                        if playbook.enabled != filters["enabled"]:
                            continue

                    if "tags" in filters:
                        if not any(t in playbook.tags for t in filters["tags"]):
                            continue

                    if "trigger_type" in filters:
                        filter_trigger = filters["trigger_type"]
                        if isinstance(filter_trigger, str):
                            filter_trigger = PlaybookTriggerType(filter_trigger)
                        if playbook.trigger.trigger_type != filter_trigger:
                            continue

                    if "author" in filters:
                        if playbook.author.lower() != filters["author"].lower():
                            continue

                    playbooks.append(playbook)

        except Exception as e:
            logger.error(f"Error listing playbooks from S3: {e}")

        return playbooks

    def list_versions(self, playbook_id: str) -> List[str]:
        """List all versions of a playbook."""
        versions = []

        try:
            prefix = f"{self.prefix}versions/{playbook_id}/"
            paginator = self.s3.get_paginator("list_objects_v2")

            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key.endswith(".yml"):
                        version = key.split("/")[-1].replace(".yml", "")
                        versions.append(version)

            # Sort by semantic version (newest first)
            def version_key(v: str) -> tuple:
                parts = v.split(".")
                return tuple(int(p) if p.isdigit() else 0 for p in parts)

            versions.sort(key=version_key, reverse=True)

        except Exception as e:
            logger.error(f"Error listing versions for {playbook_id}: {e}")

        return versions

    def save(self, playbook: Playbook) -> str:
        """Save a playbook."""
        playbook.modified = datetime.utcnow()

        try:
            # Save to current
            self._save_to_s3(playbook, self._current_key(playbook.id))

            # Save to versions
            self._save_to_s3(playbook, self._version_key(playbook.id, playbook.version))

            logger.info(f"Saved playbook {playbook.id} version {playbook.version} to S3")
            return playbook.id

        except Exception as e:
            logger.error(f"Error saving playbook {playbook.id} to S3: {e}")
            raise

    def delete(self, playbook_id: str) -> bool:
        """Delete (archive) a playbook."""
        try:
            # Get current playbook
            playbook = self.get(playbook_id)
            if not playbook:
                return False

            # Copy to archive
            self._save_to_s3(playbook, self._archive_key(playbook_id))

            # Delete from current
            self.s3.delete_object(
                Bucket=self.bucket,
                Key=self._current_key(playbook_id),
            )

            logger.info(f"Archived playbook {playbook_id} in S3")
            return True

        except Exception as e:
            logger.error(f"Error deleting playbook {playbook_id} from S3: {e}")
            return False


def get_playbook_store(
    store_type: Optional[str] = None,
    **kwargs: Any,
) -> PlaybookStore:
    """Factory function to get a playbook store instance.

    Args:
        store_type: Type of store (file, dynamodb, s3). If None, reads from
            PLAYBOOK_STORE_TYPE environment variable.
        **kwargs: Store-specific configuration

    Returns:
        PlaybookStore instance

    Raises:
        ValueError: If store type is unknown
    """
    if store_type is None:
        store_type = os.environ.get("PLAYBOOK_STORE_TYPE", "file")

    store_type = store_type.lower()

    if store_type == "file":
        base_path = kwargs.get("base_path", os.environ.get("PLAYBOOK_STORE_PATH", "rules/playbooks"))
        return FilePlaybookStore(base_path=base_path)

    elif store_type == "dynamodb":
        table_name = kwargs.get("table_name", os.environ.get("PLAYBOOK_TABLE_NAME", "mantissa_playbooks"))
        versions_table_name = kwargs.get(
            "versions_table_name",
            os.environ.get("PLAYBOOK_VERSIONS_TABLE_NAME", "mantissa_playbook_versions")
        )
        region = kwargs.get("region", os.environ.get("AWS_REGION"))
        return DynamoDBPlaybookStore(
            table_name=table_name,
            versions_table_name=versions_table_name,
            region=region,
        )

    elif store_type == "s3":
        bucket = kwargs.get("bucket", os.environ.get("PLAYBOOK_S3_BUCKET"))
        if not bucket:
            raise ValueError("S3 bucket is required for S3 playbook store")
        prefix = kwargs.get("prefix", os.environ.get("PLAYBOOK_S3_PREFIX", "playbooks/"))
        region = kwargs.get("region", os.environ.get("AWS_REGION"))
        return S3PlaybookStore(bucket=bucket, prefix=prefix, region=region)

    else:
        raise ValueError(f"Unknown playbook store type: {store_type}")
