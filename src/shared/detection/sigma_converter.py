"""Sigma rule converter for multi-cloud detection portability.

This module provides conversion from Sigma rules to cloud-specific SQL queries
using the pySigma library and backend implementations.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.athena import AthenaBackend
    from sigma.exceptions import SigmaError
    SIGMA_AVAILABLE = True
except ImportError:
    SIGMA_AVAILABLE = False
    SigmaCollection = None
    AthenaBackend = None
    SigmaError = Exception

logger = logging.getLogger(__name__)


class SigmaConversionError(Exception):
    """Raised when Sigma rule conversion fails."""
    pass


class SigmaRuleConverter:
    """Converts Sigma rules to cloud-specific SQL queries.

    Supports multiple backend types for different cloud platforms:
    - athena: AWS Athena (Presto SQL)
    - bigquery: GCP BigQuery (Standard SQL)
    - synapse: Azure Synapse Analytics (T-SQL)
    """

    SUPPORTED_BACKENDS = ["athena", "bigquery", "synapse"]

    def __init__(self, backend_type: str = "athena"):
        """Initialize Sigma rule converter.

        Args:
            backend_type: Backend type (athena, bigquery, synapse)

        Raises:
            ImportError: If pySigma is not installed
            ValueError: If backend_type is not supported
        """
        if not SIGMA_AVAILABLE:
            raise ImportError(
                "pySigma library is not installed. "
                "Install it with: pip install pysigma pysigma-backend-athena"
            )

        if backend_type not in self.SUPPORTED_BACKENDS:
            raise ValueError(
                f"Unsupported backend: {backend_type}. "
                f"Supported backends: {', '.join(self.SUPPORTED_BACKENDS)}"
            )

        self.backend_type = backend_type
        self.backend = self._create_backend(backend_type)
        self._query_cache: Dict[str, str] = {}

    def _create_backend(self, backend_type: str):
        """Create the appropriate Sigma backend.

        Args:
            backend_type: Backend type identifier

        Returns:
            Sigma backend instance

        Raises:
            ImportError: If required backend library is not installed
        """
        # Import pipeline configuration
        from .sigma_pipeline import get_mantissa_pipeline

        if backend_type == "athena":
            try:
                from sigma.backends.athena import AthenaBackend
                pipeline = get_mantissa_pipeline("athena")
                return AthenaBackend(processing_pipeline=pipeline)
            except ImportError:
                raise ImportError(
                    "Athena backend not available. "
                    "Install with: pip install pysigma-backend-athena"
                )

        elif backend_type == "bigquery":
            try:
                from sigma.backends.bigquery import BigQueryBackend
                return BigQueryBackend()
            except ImportError:
                raise ImportError(
                    "BigQuery backend not available. "
                    "Install with: pip install pysigma-backend-bigquery"
                )

        elif backend_type == "synapse":
            try:
                from sigma.backends.microsoft365defender import MicrosoftXDRBackend
                return MicrosoftXDRBackend()
            except ImportError:
                raise ImportError(
                    "Synapse/Microsoft365 backend not available. "
                    "Install with: pip install pysigma-backend-microsoft365defender"
                )

        else:
            raise ValueError(f"Unknown backend type: {backend_type}")

    def convert_rule_to_sql(
        self,
        sigma_rule: Union[str, Path, Dict[str, Any]],
        use_cache: bool = True
    ) -> str:
        """Convert a Sigma rule to SQL query.

        Args:
            sigma_rule: Path to Sigma YAML file, YAML string, or rule dict
            use_cache: Whether to use cached conversion results

        Returns:
            SQL query string

        Raises:
            SigmaConversionError: If conversion fails
        """
        # Generate cache key
        cache_key = None
        if use_cache:
            if isinstance(sigma_rule, (str, Path)):
                cache_key = f"{self.backend_type}:{sigma_rule}"
            elif isinstance(sigma_rule, dict):
                cache_key = f"{self.backend_type}:{sigma_rule.get('id', 'unknown')}"

            if cache_key and cache_key in self._query_cache:
                logger.debug(f"Using cached query for {cache_key}")
                return self._query_cache[cache_key]

        # Load Sigma rule
        try:
            sigma_collection = self._load_sigma_rule(sigma_rule)
        except Exception as e:
            raise SigmaConversionError(f"Failed to load Sigma rule: {str(e)}")

        # Convert to SQL
        try:
            queries = self.backend.convert(sigma_collection)
        except SigmaError as e:
            raise SigmaConversionError(f"Sigma conversion failed: {str(e)}")
        except Exception as e:
            raise SigmaConversionError(f"Unexpected conversion error: {str(e)}")

        if not queries:
            raise SigmaConversionError("No queries generated from Sigma rule")

        # Return first query (Sigma can generate multiple queries)
        sql_query = queries[0]

        # Cache result
        if use_cache and cache_key:
            self._query_cache[cache_key] = sql_query

        return sql_query

    def _load_sigma_rule(
        self,
        sigma_rule: Union[str, Path, Dict[str, Any]]
    ) -> SigmaCollection:
        """Load Sigma rule from various sources.

        Args:
            sigma_rule: Path to YAML file, YAML string, or rule dict

        Returns:
            SigmaCollection object

        Raises:
            ValueError: If rule format is invalid
        """
        if isinstance(sigma_rule, dict):
            # Convert dict to YAML string
            yaml_content = yaml.dump(sigma_rule)
            return SigmaCollection.from_yaml(yaml_content)

        elif isinstance(sigma_rule, Path):
            # Load from file path
            with open(sigma_rule, 'r') as f:
                yaml_content = f.read()
            return SigmaCollection.from_yaml(yaml_content)

        elif isinstance(sigma_rule, str):
            # Check if it's a file path or YAML content
            if Path(sigma_rule).exists():
                with open(sigma_rule, 'r') as f:
                    yaml_content = f.read()
            else:
                # Assume it's YAML content
                yaml_content = sigma_rule

            return SigmaCollection.from_yaml(yaml_content)

        else:
            raise ValueError(
                f"Invalid sigma_rule type: {type(sigma_rule)}. "
                "Expected str, Path, or dict"
            )

    def validate_conversion(
        self,
        sigma_rule: Union[str, Path, Dict[str, Any]]
    ) -> tuple[bool, List[str]]:
        """Validate that a Sigma rule can be converted.

        Args:
            sigma_rule: Sigma rule to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Load rule
        try:
            sigma_collection = self._load_sigma_rule(sigma_rule)
        except Exception as e:
            errors.append(f"Failed to load rule: {str(e)}")
            return False, errors

        # Extract rule dict for validation
        if sigma_collection.rules:
            rule = sigma_collection.rules[0]

            # Check logsource
            if not hasattr(rule, 'logsource') or not rule.logsource:
                errors.append("Missing or empty logsource field")
            else:
                # Validate logsource fields
                logsource = rule.logsource
                if not (hasattr(logsource, 'product') or
                        hasattr(logsource, 'service') or
                        hasattr(logsource, 'category')):
                    errors.append(
                        "Logsource must have at least one of: product, service, category"
                    )

            # Check detection
            if not hasattr(rule, 'detection') or not rule.detection:
                errors.append("Missing or empty detection field")

        # Attempt conversion
        try:
            self.convert_rule_to_sql(sigma_rule, use_cache=False)
        except SigmaConversionError as e:
            errors.append(f"Conversion failed: {str(e)}")
        except Exception as e:
            errors.append(f"Unexpected error during conversion: {str(e)}")

        return len(errors) == 0, errors

    def clear_cache(self) -> None:
        """Clear the query conversion cache."""
        self._query_cache.clear()
        logger.debug("Query cache cleared")

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        return {
            "size": len(self._query_cache),
            "backend": self.backend_type
        }


def convert_legacy_to_sigma(legacy_rule: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a legacy Mantissa rule to Sigma format.

    This is a helper function for migrating existing rules.

    Args:
        legacy_rule: Legacy rule dictionary

    Returns:
        Sigma-formatted rule dictionary

    Note:
        This is a best-effort conversion. Manual review is recommended.
    """
    sigma_rule = {
        "title": legacy_rule.get("name", ""),
        "id": legacy_rule.get("id", ""),
        "status": "stable" if legacy_rule.get("enabled", True) else "test",
        "description": legacy_rule.get("description", ""),
        "author": legacy_rule.get("author", "Mantissa Security Team"),
        "date": legacy_rule.get("created", ""),
    }

    # Add modified date if present
    if "modified" in legacy_rule:
        sigma_rule["modified"] = legacy_rule["modified"]

    # Map severity
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "informational"
    }
    sigma_rule["level"] = severity_map.get(
        legacy_rule.get("severity", "medium"),
        "medium"
    )

    # Add logsource (requires manual mapping)
    sigma_rule["logsource"] = {
        "product": "aws",
        "service": "cloudtrail"  # Default, should be customized
    }

    # Detection - cannot auto-convert SQL to Sigma detection logic
    # This requires manual conversion
    sigma_rule["detection"] = {
        "_comment": "Manual conversion required from SQL",
        "condition": "selection"
    }

    # Add tags
    tags = []
    if "tags" in legacy_rule:
        tags.extend(legacy_rule["tags"])

    # Add MITRE ATT&CK tags
    if "mitre_attack" in legacy_rule.get("metadata", {}):
        for technique in legacy_rule["metadata"]["mitre_attack"]:
            tags.append(f"attack.{technique.lower().replace('-', '_')}")

    if tags:
        sigma_rule["tags"] = tags

    # Add false positives
    if "false_positives" in legacy_rule.get("metadata", {}):
        sigma_rule["falsepositives"] = legacy_rule["metadata"]["false_positives"]

    # Add references
    if "references" in legacy_rule.get("metadata", {}):
        sigma_rule["references"] = legacy_rule["metadata"]["references"]

    # Add fields to include in output
    sigma_rule["fields"] = []

    return sigma_rule
