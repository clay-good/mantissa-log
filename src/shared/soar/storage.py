"""SOAR storage - re-export playbook stores for package compatibility.

This module provides convenient imports for playbook storage implementations.
"""

from .playbook_store import (
    PlaybookStore,
    FilePlaybookStore,
    DynamoDBPlaybookStore,
    S3PlaybookStore,
)

# Aliases for compatibility
PlaybookStorage = PlaybookStore
InMemoryPlaybookStore = FilePlaybookStore  # Alias for in-memory/file storage
FilePlaybookStorage = FilePlaybookStore  # Alias matching test expectations

__all__ = [
    "PlaybookStore",
    "PlaybookStorage",
    "FilePlaybookStore",
    "FilePlaybookStorage",
    "InMemoryPlaybookStore",
    "DynamoDBPlaybookStore",
    "S3PlaybookStore",
]
