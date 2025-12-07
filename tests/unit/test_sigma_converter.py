"""Unit tests for Sigma rule converter."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from src.shared.detection.sigma_converter import (
    SigmaRuleConverter,
    SigmaConversionError,
    SIGMA_AVAILABLE,
)


@pytest.fixture
def sample_sigma_rule():
    """Sample Sigma rule for testing."""
    return {
        "title": "Test Rule",
        "id": "test-rule-001",
        "status": "stable",
        "description": "Test description",
        "author": "Test Author",
        "date": "2025-01-27",
        "logsource": {
            "product": "aws",
            "service": "cloudtrail"
        },
        "detection": {
            "selection": {
                "eventName": "ConsoleLogin",
                "errorCode": "Failed authentication"
            },
            "condition": "selection"
        },
        "fields": ["sourceIPAddress", "userIdentity.principalId"],
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1110"]
    }


@pytest.mark.skipif(not SIGMA_AVAILABLE, reason="pySigma not installed")
class TestSigmaRuleConverter:
    """Tests for SigmaRuleConverter class."""

    def test_init_athena_backend(self):
        """Test initialization with Athena backend."""
        converter = SigmaRuleConverter(backend_type="athena")
        assert converter.backend_type == "athena"
        assert converter.backend is not None

    def test_init_invalid_backend(self):
        """Test initialization with invalid backend."""
        with pytest.raises(ValueError, match="Unsupported backend"):
            SigmaRuleConverter(backend_type="invalid")

    def test_supported_backends(self):
        """Test that supported backends list is correct."""
        assert "athena" in SigmaRuleConverter.SUPPORTED_BACKENDS
        assert "bigquery" in SigmaRuleConverter.SUPPORTED_BACKENDS
        assert "synapse" in SigmaRuleConverter.SUPPORTED_BACKENDS

    def test_convert_rule_to_sql_dict(self, sample_sigma_rule):
        """Test converting Sigma rule dict to SQL."""
        converter = SigmaRuleConverter(backend_type="athena")

        # Mock the backend conversion
        with patch.object(converter.backend, 'convert') as mock_convert:
            mock_convert.return_value = ["SELECT * FROM cloudtrail"]

            sql = converter.convert_rule_to_sql(sample_sigma_rule, use_cache=False)

            assert sql is not None
            assert isinstance(sql, str)
            assert len(sql) > 0

    def test_convert_rule_caching(self, sample_sigma_rule):
        """Test that query conversion is cached."""
        converter = SigmaRuleConverter(backend_type="athena")

        with patch.object(converter.backend, 'convert') as mock_convert:
            mock_convert.return_value = ["SELECT * FROM cloudtrail"]

            # First call
            sql1 = converter.convert_rule_to_sql(sample_sigma_rule, use_cache=True)

            # Second call should use cache
            sql2 = converter.convert_rule_to_sql(sample_sigma_rule, use_cache=True)

            assert sql1 == sql2
            # Backend convert should only be called once
            assert mock_convert.call_count == 1

    def test_convert_rule_no_cache(self, sample_sigma_rule):
        """Test conversion without caching."""
        converter = SigmaRuleConverter(backend_type="athena")

        with patch.object(converter.backend, 'convert') as mock_convert:
            mock_convert.return_value = ["SELECT * FROM cloudtrail"]

            # First call
            sql1 = converter.convert_rule_to_sql(sample_sigma_rule, use_cache=False)

            # Second call should NOT use cache
            sql2 = converter.convert_rule_to_sql(sample_sigma_rule, use_cache=False)

            assert sql1 == sql2
            # Backend convert should be called twice
            assert mock_convert.call_count == 2

    def test_validate_conversion_valid_rule(self, sample_sigma_rule):
        """Test validation of a valid Sigma rule."""
        converter = SigmaRuleConverter(backend_type="athena")

        with patch.object(converter.backend, 'convert') as mock_convert:
            mock_convert.return_value = ["SELECT * FROM cloudtrail"]

            is_valid, errors = converter.validate_conversion(sample_sigma_rule)

            assert is_valid is True
            assert len(errors) == 0

    def test_validate_conversion_missing_logsource(self):
        """Test validation with missing logsource."""
        converter = SigmaRuleConverter(backend_type="athena")

        invalid_rule = {
            "title": "Test",
            "detection": {"selection": {}, "condition": "selection"}
        }

        is_valid, errors = converter.validate_conversion(invalid_rule)

        assert is_valid is False
        assert any("logsource" in error.lower() for error in errors)

    def test_validate_conversion_missing_detection(self, sample_sigma_rule):
        """Test validation with missing detection."""
        converter = SigmaRuleConverter(backend_type="athena")

        # Remove detection field
        invalid_rule = sample_sigma_rule.copy()
        del invalid_rule["detection"]

        is_valid, errors = converter.validate_conversion(invalid_rule)

        assert is_valid is False
        assert any("detection" in error.lower() for error in errors)

    def test_clear_cache(self, sample_sigma_rule):
        """Test cache clearing."""
        converter = SigmaRuleConverter(backend_type="athena")

        with patch.object(converter.backend, 'convert') as mock_convert:
            mock_convert.return_value = ["SELECT * FROM cloudtrail"]

            # Add to cache
            converter.convert_rule_to_sql(sample_sigma_rule, use_cache=True)
            assert converter.get_cache_stats()["size"] > 0

            # Clear cache
            converter.clear_cache()
            assert converter.get_cache_stats()["size"] == 0

    def test_get_cache_stats(self):
        """Test cache statistics."""
        converter = SigmaRuleConverter(backend_type="athena")

        stats = converter.get_cache_stats()

        assert "size" in stats
        assert "backend" in stats
        assert stats["backend"] == "athena"
        assert stats["size"] == 0


@pytest.mark.skipif(SIGMA_AVAILABLE, reason="Test for when pySigma is not available")
class TestSigmaNotAvailable:
    """Tests for when pySigma is not installed."""

    def test_init_raises_import_error(self):
        """Test that initialization raises ImportError when pySigma not available."""
        with pytest.raises(ImportError, match="pySigma library is not installed"):
            SigmaRuleConverter(backend_type="athena")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
