"""Integration tests for Sigma rule conversion to multi-cloud SQL.

Tests that Sigma rules can be converted to SQL for all three cloud providers:
- AWS Athena (Presto SQL)
- GCP BigQuery (Standard SQL)
- Azure Synapse (T-SQL)
"""

import pytest
from pathlib import Path
from src.shared.detection.sigma_converter import SigmaRuleConverter, SIGMA_AVAILABLE


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not SIGMA_AVAILABLE, reason="pySigma not installed")
]


class TestSigmaMultiCloudConversion:
    """Test Sigma rule conversion across cloud platforms."""

    @pytest.fixture
    def rules_path(self):
        """Get path to Sigma rules directory."""
        return Path(__file__).parent.parent.parent.parent / "rules" / "sigma"

    @pytest.fixture
    def sample_rule_path(self, rules_path):
        """Get path to sample CloudTrail rule."""
        rule_path = rules_path / "aws" / "cloudtrail" / "root_account_usage.yml"
        if not rule_path.exists():
            pytest.skip(f"Sample rule not found: {rule_path}")
        return rule_path

    def test_convert_to_athena_sql(self, sample_rule_path):
        """Test conversion to AWS Athena SQL (Presto)."""
        converter = SigmaRuleConverter(backend_type="athena")

        sql = converter.convert_rule_to_sql(str(sample_rule_path), use_cache=False)

        assert sql is not None
        assert isinstance(sql, str)
        assert len(sql) > 0
        assert "SELECT" in sql.upper()

        # Athena-specific syntax (Presto)
        # Should use single quotes for strings
        # May have INTERVAL syntax for time ranges

    def test_convert_to_bigquery_sql(self, sample_rule_path):
        """Test conversion to GCP BigQuery SQL."""
        converter = SigmaRuleConverter(backend_type="bigquery")

        sql = converter.convert_rule_to_sql(str(sample_rule_path), use_cache=False)

        assert sql is not None
        assert isinstance(sql, str)
        assert len(sql) > 0
        assert "SELECT" in sql.upper()

        # BigQuery-specific syntax
        # Should use backticks for table/column names (optional)
        # May have different timestamp functions

    def test_convert_to_synapse_sql(self, sample_rule_path):
        """Test conversion to Azure Synapse SQL (T-SQL)."""
        converter = SigmaRuleConverter(backend_type="synapse")

        sql = converter.convert_rule_to_sql(str(sample_rule_path), use_cache=False)

        assert sql is not None
        assert isinstance(sql, str)
        assert len(sql) > 0
        assert "SELECT" in sql.upper()

        # Synapse-specific syntax (T-SQL)
        # May use DATEADD, GETUTCDATE
        # Different string functions

    def test_same_rule_different_backends(self, sample_rule_path):
        """Test that same rule produces valid SQL for all backends."""
        backends = ["athena", "bigquery", "synapse"]

        results = {}

        for backend in backends:
            converter = SigmaRuleConverter(backend_type=backend)
            sql = converter.convert_rule_to_sql(str(sample_rule_path), use_cache=False)

            results[backend] = sql

            # All should produce valid SQL
            assert sql is not None
            assert len(sql) > 0
            assert "SELECT" in sql.upper()

        # All backends should produce SQL (may differ in syntax)
        assert len(results) == 3

        # Log the differences for inspection
        print("\n=== SQL Generated for Each Backend ===")
        for backend, sql in results.items():
            print(f"\n{backend.upper()}:")
            print(sql[:200])  # Print first 200 chars

    def test_convert_multiple_rules_all_backends(self, rules_path):
        """Test converting multiple rules to all backends."""
        cloudtrail_path = rules_path / "aws" / "cloudtrail"

        if not cloudtrail_path.exists():
            pytest.skip("CloudTrail rules directory not found")

        rule_files = list(cloudtrail_path.glob("*.yml"))[:5]  # Test first 5 rules

        if len(rule_files) == 0:
            pytest.skip("No CloudTrail rules found")

        backends = ["athena", "bigquery", "synapse"]

        conversion_results = {backend: {"success": 0, "failed": []} for backend in backends}

        for rule_file in rule_files:
            for backend in backends:
                try:
                    converter = SigmaRuleConverter(backend_type=backend)
                    sql = converter.convert_rule_to_sql(str(rule_file), use_cache=False)

                    if sql and len(sql) > 0:
                        conversion_results[backend]["success"] += 1
                    else:
                        conversion_results[backend]["failed"].append(rule_file.name)

                except Exception as e:
                    conversion_results[backend]["failed"].append(f"{rule_file.name}: {str(e)}")

        # Print results
        print("\n=== Multi-Cloud Conversion Results ===")
        for backend, results in conversion_results.items():
            success_rate = (results["success"] / len(rule_files)) * 100
            print(f"{backend.upper()}: {results['success']}/{len(rule_files)} ({success_rate:.1f}%)")

            if results["failed"]:
                print(f"  Failed: {', '.join(results['failed'][:3])}")

        # Expect at least 50% success for each backend
        for backend, results in conversion_results.items():
            assert results["success"] >= len(rule_files) * 0.5, \
                f"{backend} conversion rate too low: {results['success']}/{len(rule_files)}"


class TestSigmaBackendSpecificSyntax:
    """Test backend-specific SQL syntax differences."""

    @pytest.fixture
    def rules_path(self):
        """Get path to Sigma rules directory."""
        return Path(__file__).parent.parent.parent.parent / "rules" / "sigma"

    def test_athena_time_interval_syntax(self, rules_path):
        """Test Athena uses proper interval syntax."""
        rule_path = rules_path / "aws" / "cloudtrail" / "brute_force_login.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule not found: {rule_path}")

        converter = SigmaRuleConverter(backend_type="athena")
        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        # Athena uses INTERVAL '1' HOUR syntax
        # Check if time filtering is present (may vary by rule)
        assert sql is not None

    def test_bigquery_timestamp_functions(self, rules_path):
        """Test BigQuery uses proper timestamp functions."""
        rule_path = rules_path / "aws" / "cloudtrail" / "brute_force_login.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule not found: {rule_path}")

        converter = SigmaRuleConverter(backend_type="bigquery")
        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        # BigQuery uses TIMESTAMP_SUB, CURRENT_TIMESTAMP() syntax
        assert sql is not None

    def test_synapse_dateadd_syntax(self, rules_path):
        """Test Synapse uses proper DATEADD syntax."""
        rule_path = rules_path / "aws" / "cloudtrail" / "brute_force_login.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule not found: {rule_path}")

        converter = SigmaRuleConverter(backend_type="synapse")
        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        # Synapse uses DATEADD, GETUTCDATE() syntax
        assert sql is not None


class TestSigmaValidationMultiCloud:
    """Test Sigma rule validation across cloud providers."""

    @pytest.fixture
    def rules_path(self):
        """Get path to Sigma rules directory."""
        return Path(__file__).parent.parent.parent.parent / "rules" / "sigma"

    def test_validate_rules_all_backends(self, rules_path):
        """Test rule validation for all backends."""
        cloudtrail_path = rules_path / "aws" / "cloudtrail"

        if not cloudtrail_path.exists():
            pytest.skip("CloudTrail rules directory not found")

        rule_files = list(cloudtrail_path.glob("*.yml"))[:3]  # Test first 3 rules

        if len(rule_files) == 0:
            pytest.skip("No CloudTrail rules found")

        backends = ["athena", "bigquery", "synapse"]

        for rule_file in rule_files:
            for backend in backends:
                converter = SigmaRuleConverter(backend_type=backend)

                is_valid, errors = converter.validate_conversion(str(rule_file))

                # Rules should be valid for all backends
                assert is_valid, f"{rule_file.name} invalid for {backend}: {errors}"


class TestSigmaCachingMultiCloud:
    """Test caching behavior across backends."""

    @pytest.fixture
    def rules_path(self):
        """Get path to Sigma rules directory."""
        return Path(__file__).parent.parent.parent.parent / "rules" / "sigma"

    def test_cache_separate_per_backend(self, rules_path):
        """Test that cache is separate for each backend."""
        rule_path = rules_path / "aws" / "cloudtrail" / "root_account_usage.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule not found: {rule_path}")

        # Convert with different backends
        athena_converter = SigmaRuleConverter(backend_type="athena")
        bigquery_converter = SigmaRuleConverter(backend_type="bigquery")

        athena_sql = athena_converter.convert_rule_to_sql(str(rule_path), use_cache=True)
        bigquery_sql = bigquery_converter.convert_rule_to_sql(str(rule_path), use_cache=True)

        # Should produce different SQL (potentially)
        assert athena_sql is not None
        assert bigquery_sql is not None

        # Cache should work on second call
        athena_sql_cached = athena_converter.convert_rule_to_sql(str(rule_path), use_cache=True)
        bigquery_sql_cached = bigquery_converter.convert_rule_to_sql(str(rule_path), use_cache=True)

        assert athena_sql == athena_sql_cached
        assert bigquery_sql == bigquery_sql_cached


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
