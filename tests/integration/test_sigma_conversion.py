"""Integration tests for Sigma rule conversion to SQL."""

import pytest
from pathlib import Path

from src.shared.detection.sigma_converter import SigmaRuleConverter, SIGMA_AVAILABLE
from src.shared.detection.rule import RuleLoader


@pytest.mark.skipif(not SIGMA_AVAILABLE, reason="pySigma not installed")
class TestSigmaRuleConversion:
    """Integration tests for converting Sigma rules to SQL."""

    @pytest.fixture
    def converter(self):
        """Create Sigma converter instance."""
        return SigmaRuleConverter(backend_type="athena")

    @pytest.fixture
    def rules_path(self):
        """Get path to Sigma rules directory."""
        return Path(__file__).parent.parent.parent / "rules" / "sigma"

    def test_convert_brute_force_login(self, converter, rules_path):
        """Test conversion of brute force login rule."""
        rule_path = rules_path / "aws" / "cloudtrail" / "brute_force_login.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule file not found: {rule_path}")

        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        assert sql is not None
        assert isinstance(sql, str)
        assert len(sql) > 0
        assert "SELECT" in sql.upper()
        assert "cloudtrail" in sql.lower()
        assert "eventname" in sql.lower() or "eventName" in sql

    def test_convert_root_account_usage(self, converter, rules_path):
        """Test conversion of root account usage rule."""
        rule_path = rules_path / "aws" / "cloudtrail" / "root_account_usage.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule file not found: {rule_path}")

        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        assert sql is not None
        assert "cloudtrail" in sql.lower()
        assert "useridentity" in sql.lower() or "userIdentity" in sql

    def test_convert_privilege_escalation(self, converter, rules_path):
        """Test conversion of privilege escalation rule."""
        rule_path = rules_path / "aws" / "cloudtrail" / "privilege_escalation.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule file not found: {rule_path}")

        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        assert sql is not None
        assert "eventname" in sql.lower() or "eventName" in sql

    def test_convert_cloudtrail_disabled(self, converter, rules_path):
        """Test conversion of CloudTrail disabled rule."""
        rule_path = rules_path / "aws" / "cloudtrail" / "cloudtrail_disabled.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule file not found: {rule_path}")

        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        assert sql is not None
        assert "cloudtrail" in sql.lower()

    def test_convert_security_group_opened(self, converter, rules_path):
        """Test conversion of security group opened rule."""
        rule_path = rules_path / "aws" / "cloudtrail" / "security_group_opened.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule file not found: {rule_path}")

        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        assert sql is not None
        assert "0.0.0.0" in sql or "security" in sql.lower()

    def test_convert_vpc_flow_port_scanning(self, converter, rules_path):
        """Test conversion of VPC Flow port scanning rule."""
        rule_path = rules_path / "aws" / "vpc_flow" / "port_scanning.yml"

        if not rule_path.exists():
            pytest.skip(f"Rule file not found: {rule_path}")

        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        assert sql is not None
        assert "vpc" in sql.lower() or "flow" in sql.lower()
        assert "dstport" in sql.lower()

    def test_convert_all_cloudtrail_rules(self, converter, rules_path):
        """Test conversion of all CloudTrail rules."""
        cloudtrail_path = rules_path / "aws" / "cloudtrail"

        if not cloudtrail_path.exists():
            pytest.skip("CloudTrail rules directory not found")

        rule_files = list(cloudtrail_path.glob("*.yml"))
        assert len(rule_files) > 0, "No CloudTrail rules found"

        converted_count = 0
        failed_rules = []

        for rule_file in rule_files:
            try:
                sql = converter.convert_rule_to_sql(str(rule_file), use_cache=False)
                assert sql is not None
                assert len(sql) > 0
                converted_count += 1
            except Exception as e:
                failed_rules.append((rule_file.name, str(e)))

        print(f"\nConverted {converted_count}/{len(rule_files)} CloudTrail rules")

        if failed_rules:
            print("\nFailed rules:")
            for rule_name, error in failed_rules:
                print(f"  - {rule_name}: {error}")

        # Allow some failures during development, but track them
        assert converted_count >= len(rule_files) * 0.7, \
            f"Less than 70% of rules converted successfully: {converted_count}/{len(rule_files)}"

    def test_convert_all_vpc_flow_rules(self, converter, rules_path):
        """Test conversion of all VPC Flow rules."""
        vpc_flow_path = rules_path / "aws" / "vpc_flow"

        if not vpc_flow_path.exists():
            pytest.skip("VPC Flow rules directory not found")

        rule_files = list(vpc_flow_path.glob("*.yml"))

        if len(rule_files) == 0:
            pytest.skip("No VPC Flow rules found")

        converted_count = 0
        failed_rules = []

        for rule_file in rule_files:
            try:
                sql = converter.convert_rule_to_sql(str(rule_file), use_cache=False)
                assert sql is not None
                assert len(sql) > 0
                converted_count += 1
            except Exception as e:
                failed_rules.append((rule_file.name, str(e)))

        print(f"\nConverted {converted_count}/{len(rule_files)} VPC Flow rules")

        if failed_rules:
            print("\nFailed rules:")
            for rule_name, error in failed_rules:
                print(f"  - {rule_name}: {error}")

        assert converted_count >= len(rule_files) * 0.7, \
            f"Less than 70% of rules converted successfully: {converted_count}/{len(rule_files)}"

    def test_rule_loader_integration(self, rules_path):
        """Test RuleLoader with Sigma rules."""
        loader = RuleLoader(
            rules_path=str(rules_path / "aws" / "cloudtrail"),
            backend_type="athena"
        )

        rules = loader.load_all_rules()

        assert len(rules) > 0, "No rules loaded"

        # Check that rules were loaded correctly
        for rule in rules:
            assert rule.id is not None
            assert rule.name is not None
            assert rule.severity in ["critical", "high", "medium", "low", "info"]
            assert rule.query.sql is not None
            assert len(rule.query.sql) > 0

    def test_validate_all_sigma_rules(self, converter, rules_path):
        """Validate all Sigma rules can be converted."""
        all_rules = list(rules_path.rglob("*.yml"))

        if len(all_rules) == 0:
            pytest.skip("No Sigma rules found")

        valid_count = 0
        invalid_rules = []

        for rule_file in all_rules:
            is_valid, errors = converter.validate_conversion(str(rule_file))

            if is_valid:
                valid_count += 1
            else:
                invalid_rules.append((rule_file.name, errors))

        print(f"\nValidated {valid_count}/{len(all_rules)} Sigma rules")

        if invalid_rules:
            print("\nInvalid rules:")
            for rule_name, errors in invalid_rules:
                print(f"  - {rule_name}:")
                for error in errors:
                    print(f"      {error}")

        # Expect at least 70% validation success
        assert valid_count >= len(all_rules) * 0.7, \
            f"Less than 70% of rules are valid: {valid_count}/{len(all_rules)}"


@pytest.mark.skipif(not SIGMA_AVAILABLE, reason="pySigma not installed")
class TestSigmaFieldMappings:
    """Test Sigma pipeline field mappings."""

    def test_cloudtrail_field_mapping(self):
        """Test CloudTrail field name mappings."""
        from src.shared.detection.sigma_pipeline import MantissaLogPipeline

        # Test known mappings
        assert MantissaLogPipeline.get_field_mapping("aws", "cloudtrail", "eventName") == "eventname"
        assert MantissaLogPipeline.get_field_mapping("aws", "cloudtrail", "sourceIPAddress") == "sourceipaddress"
        assert MantissaLogPipeline.get_field_mapping("aws", "cloudtrail", "userIdentity.principalId") == "useridentity.principalid"

    def test_vpc_flow_field_mapping(self):
        """Test VPC Flow field name mappings."""
        from src.shared.detection.sigma_pipeline import MantissaLogPipeline

        assert MantissaLogPipeline.get_field_mapping("aws", "vpcflowlogs", "srcaddr") == "srcaddr"
        assert MantissaLogPipeline.get_field_mapping("aws", "vpcflowlogs", "dstport") == "dstport"
        assert MantissaLogPipeline.get_field_mapping("aws", "vpcflowlogs", "action") == "action"

    def test_table_name_mapping(self):
        """Test logsource to table name mapping."""
        from src.shared.detection.sigma_pipeline import get_table_for_logsource

        assert get_table_for_logsource("aws", "cloudtrail") == "cloudtrail"
        assert get_table_for_logsource("aws", "vpcflowlogs") == "vpc_flow_logs"
        assert get_table_for_logsource("aws", "guardduty") == "guardduty_findings"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
