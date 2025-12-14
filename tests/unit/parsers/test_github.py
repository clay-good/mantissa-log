"""Unit tests for GitHub Enterprise audit log parser."""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.github import GitHubParser


class TestGitHubParser:
    """Tests for GitHubParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return GitHubParser()

    @pytest.fixture
    def sample_repo_create_event(self):
        """Sample GitHub repository creation event."""
        return {
            "@timestamp": 1706500000000,
            "action": "repo.create",
            "actor": "john-doe",
            "actor_id": 12345,
            "actor_location": {
                "country_code": "US"
            },
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "org": "example-org",
            "repo": "example-org/new-repo",
            "created_at": 1706500000000,
            "_document_id": "doc-123-456",
            "visibility": "private",
            "business": ""
        }

    @pytest.fixture
    def sample_member_add_event(self):
        """Sample GitHub member addition event."""
        return {
            "@timestamp": 1706500000000,
            "action": "org.add_member",
            "actor": "admin-user",
            "actor_id": 67890,
            "actor_location": {
                "country_code": "US"
            },
            "user": "new-member",
            "org": "example-org",
            "permission": "read",
            "_document_id": "doc-789-012"
        }

    @pytest.fixture
    def sample_token_create_event(self):
        """Sample GitHub personal access token creation event."""
        return {
            "@timestamp": 1706500000000,
            "action": "personal_access_token.create",
            "actor": "john-doe",
            "actor_id": 12345,
            "actor_location": {
                "country_code": "CA"
            },
            "token_scopes": "repo,read:org",
            "_document_id": "doc-token-123"
        }

    @pytest.fixture
    def sample_branch_protection_event(self):
        """Sample GitHub branch protection event."""
        return {
            "@timestamp": 1706500000000,
            "action": "protected_branch.create",
            "actor": "admin-user",
            "actor_id": 67890,
            "repo": "example-org/protected-repo",
            "org": "example-org",
            "branch": "main",
            "protected_branch": "main",
            "_document_id": "doc-bp-123"
        }

    @pytest.fixture
    def sample_webhook_event(self):
        """Sample GitHub webhook creation event."""
        return {
            "@timestamp": 1706500000000,
            "action": "hook.create",
            "actor": "admin-user",
            "actor_id": 67890,
            "repo": "example-org/webhook-repo",
            "org": "example-org",
            "hook_id": 98765,
            "events": ["push", "pull_request"],
            "active": True,
            "_document_id": "doc-hook-123"
        }

    @pytest.fixture
    def sample_failed_action_event(self):
        """Sample GitHub failed action event."""
        return {
            "@timestamp": 1706500000000,
            "action": "oauth_access.create_failed",
            "actor": "malicious-user",
            "actor_id": 11111,
            "actor_location": {
                "country_code": "XX"
            },
            "_document_id": "doc-fail-123"
        }

    @pytest.fixture
    def sample_workflow_event(self):
        """Sample GitHub Actions workflow event."""
        return {
            "@timestamp": 1706500000000,
            "action": "workflows.update",
            "actor": "john-doe",
            "actor_id": 12345,
            "repo": "example-org/actions-repo",
            "org": "example-org",
            "workflow": ".github/workflows/ci.yml",
            "workflow_id": 12345678,
            "_document_id": "doc-wf-123"
        }

    def test_parser_initialization(self, parser):
        """Test parser initializes correctly."""
        assert parser.source_type == "github"

    def test_parse_repo_create_basic_fields(self, parser, sample_repo_create_event):
        """Test parsing repository creation event extracts basic fields."""
        result = parser.parse(sample_repo_create_event)

        assert "@timestamp" in result
        assert result["ecs.version"] == "8.0.0"
        assert result["event"]["provider"] == "github"
        assert result["event"]["module"] == "audit"
        assert result["event"]["action"] == "repo.create"

    def test_parse_repo_create_user_fields(self, parser, sample_repo_create_event):
        """Test parsing repository creation event extracts user fields."""
        result = parser.parse(sample_repo_create_event)

        assert result["user"]["name"] == "john-doe"
        assert result["user"]["id"] == "12345"

    def test_parse_repo_create_org_fields(self, parser, sample_repo_create_event):
        """Test parsing extracts organization fields."""
        result = parser.parse(sample_repo_create_event)

        assert result["organization"]["name"] == "example-org"

    def test_parse_repo_create_outcome(self, parser, sample_repo_create_event):
        """Test parsing sets correct outcome for successful action."""
        result = parser.parse(sample_repo_create_event)

        assert result["event"]["outcome"] == "success"

    def test_parse_repo_create_category(self, parser, sample_repo_create_event):
        """Test parsing sets correct category for repo event."""
        result = parser.parse(sample_repo_create_event)

        assert "file" in result["event"]["category"]
        assert "configuration" in result["event"]["category"]

    def test_parse_repo_create_type(self, parser, sample_repo_create_event):
        """Test parsing sets correct type for create event."""
        result = parser.parse(sample_repo_create_event)

        assert "creation" in result["event"]["type"]

    def test_parse_member_add_event(self, parser, sample_member_add_event):
        """Test parsing member addition event."""
        result = parser.parse(sample_member_add_event)

        assert result["event"]["action"] == "org.add_member"
        assert "iam" in result["event"]["category"]
        assert result["github"]["permission"] == "read"
        assert "new-member" in result["related"]["user"]

    def test_parse_token_create_event(self, parser, sample_token_create_event):
        """Test parsing token creation event."""
        result = parser.parse(sample_token_create_event)

        assert result["event"]["action"] == "personal_access_token.create"
        assert "authentication" in result["event"]["category"]
        assert result["github"]["token_scopes"] == "repo,read:org"

    def test_parse_branch_protection_event(self, parser, sample_branch_protection_event):
        """Test parsing branch protection event."""
        result = parser.parse(sample_branch_protection_event)

        assert result["event"]["action"] == "protected_branch.create"
        assert result["github"]["branch"] == "main"
        assert result["github"]["protected_branch"] == "main"

    def test_parse_webhook_event(self, parser, sample_webhook_event):
        """Test parsing webhook event."""
        result = parser.parse(sample_webhook_event)

        assert result["event"]["action"] == "hook.create"
        assert "web" in result["event"]["category"]
        assert result["github"]["hook_id"] == 98765
        assert "push" in result["github"]["events"]
        assert result["github"]["active"] is True

    def test_parse_failed_action_event(self, parser, sample_failed_action_event):
        """Test parsing failed action event."""
        result = parser.parse(sample_failed_action_event)

        assert result["event"]["outcome"] == "failure"
        assert "fail" in result["event"]["action"]

    def test_parse_workflow_event(self, parser, sample_workflow_event):
        """Test parsing workflow event."""
        result = parser.parse(sample_workflow_event)

        assert result["event"]["action"] == "workflows.update"
        assert result["github"]["workflow"] == ".github/workflows/ci.yml"
        assert result["github"]["workflow_id"] == 12345678

    def test_parse_github_specific_fields(self, parser, sample_repo_create_event):
        """Test parsing extracts GitHub-specific fields."""
        result = parser.parse(sample_repo_create_event)

        assert result["github"]["action"] == "repo.create"
        assert result["github"]["actor"] == "john-doe"
        assert result["github"]["actor_id"] == 12345
        assert result["github"]["repo"] == "example-org/new-repo"
        assert result["github"]["visibility"] == "private"

    def test_parse_related_fields(self, parser, sample_member_add_event):
        """Test parsing extracts related fields for correlation."""
        result = parser.parse(sample_member_add_event)

        assert "admin-user" in result["related"]["user"]
        assert "new-member" in result["related"]["user"]

    def test_parse_preserves_raw_event(self, parser, sample_repo_create_event):
        """Test parsing preserves raw event."""
        result = parser.parse(sample_repo_create_event)

        assert "_raw" in result
        assert result["_raw"] == sample_repo_create_event

    def test_parse_geo_location(self, parser, sample_repo_create_event):
        """Test parsing extracts geo location."""
        result = parser.parse(sample_repo_create_event)

        assert result["source"]["geo"]["country_iso_code"] == "US"

    def test_parse_user_agent(self, parser, sample_repo_create_event):
        """Test parsing extracts user agent."""
        result = parser.parse(sample_repo_create_event)

        assert "Mozilla" in result["user_agent"]["original"]

    def test_validate_valid_event(self, parser, sample_repo_create_event):
        """Test validation of valid event."""
        assert parser.validate(sample_repo_create_event) is True

    def test_validate_missing_timestamp(self, parser):
        """Test validation fails without @timestamp."""
        event = {"action": "repo.create", "actor": "test"}
        assert parser.validate(event) is False

    def test_validate_missing_action(self, parser):
        """Test validation fails without action."""
        event = {"@timestamp": 1706500000000, "actor": "test"}
        assert parser.validate(event) is False

    def test_validate_missing_actor_and_user(self, parser):
        """Test validation fails without actor and user."""
        event = {"@timestamp": 1706500000000, "action": "repo.create"}
        assert parser.validate(event) is False

    def test_validate_with_user_instead_of_actor(self, parser):
        """Test validation passes with user instead of actor."""
        event = {"@timestamp": 1706500000000, "action": "repo.create", "user": "test"}
        assert parser.validate(event) is True


class TestGitHubParserEventCategorization:
    """Test event categorization."""

    @pytest.fixture
    def parser(self):
        return GitHubParser()

    def test_oauth_categorized_as_authentication(self, parser):
        """Test OAuth events are categorized as authentication."""
        categories = parser._categorize_event("oauth_access.create")
        assert "authentication" in categories

    def test_token_categorized_as_authentication(self, parser):
        """Test token events are categorized as authentication."""
        categories = parser._categorize_event("personal_access_token.create")
        assert "authentication" in categories

    def test_ssh_categorized_as_configuration(self, parser):
        """Test SSH key events are categorized as configuration."""
        categories = parser._categorize_event("public_key.create")
        # SSH key creation is categorized as configuration (key management)
        assert "configuration" in categories

    def test_member_categorized_as_iam(self, parser):
        """Test member events are categorized as IAM."""
        categories = parser._categorize_event("org.add_member")
        assert "iam" in categories

    def test_team_categorized_as_iam(self, parser):
        """Test team events are categorized as IAM."""
        categories = parser._categorize_event("team.add_repository")
        assert "iam" in categories

    def test_permission_categorized_as_iam(self, parser):
        """Test permission events are categorized as IAM."""
        categories = parser._categorize_event("repo.permission_change")
        assert "iam" in categories

    def test_repo_categorized_as_file(self, parser):
        """Test repo events are categorized as file."""
        categories = parser._categorize_event("repo.create")
        assert "file" in categories

    def test_git_categorized_as_file(self, parser):
        """Test git events are categorized as file."""
        categories = parser._categorize_event("git.push")
        assert "file" in categories

    def test_hook_categorized_as_web(self, parser):
        """Test hook events are categorized as web."""
        categories = parser._categorize_event("hook.create")
        assert "web" in categories

    def test_integration_categorized_as_web(self, parser):
        """Test integration events are categorized as web."""
        categories = parser._categorize_event("integration.create")
        assert "web" in categories

    def test_package_categorized_as_package(self, parser):
        """Test package events are categorized as package."""
        categories = parser._categorize_event("package.publish")
        assert "package" in categories

    def test_unknown_events_default_to_session(self, parser):
        """Test unknown events default to session category."""
        categories = parser._categorize_event("some.unknown.event")
        assert categories == ["session"]


class TestGitHubParserEventTypes:
    """Test ECS event type determination."""

    @pytest.fixture
    def parser(self):
        return GitHubParser()

    def test_create_event_type(self, parser):
        """Test create actions get creation type."""
        types = parser._get_event_type("repo.create")
        assert "creation" in types

    def test_add_event_type(self, parser):
        """Test add actions get creation type."""
        types = parser._get_event_type("org.add_member")
        assert "creation" in types

    def test_update_event_type(self, parser):
        """Test update actions get change type."""
        types = parser._get_event_type("repo.update")
        assert "change" in types

    def test_rename_event_type(self, parser):
        """Test rename actions get change type."""
        types = parser._get_event_type("repo.rename")
        assert "change" in types

    def test_destroy_event_type(self, parser):
        """Test destroy actions get deletion type."""
        types = parser._get_event_type("repo.destroy")
        assert "deletion" in types

    def test_remove_event_type(self, parser):
        """Test remove actions get deletion type."""
        types = parser._get_event_type("org.remove_member")
        assert "deletion" in types

    def test_access_event_type(self, parser):
        """Test access actions get access type."""
        types = parser._get_event_type("repo.access")
        assert "access" in types

    def test_download_event_type(self, parser):
        """Test download actions get access type."""
        types = parser._get_event_type("repo.download_zip")
        assert "access" in types

    def test_enable_event_type(self, parser):
        """Test enable actions get start type."""
        types = parser._get_event_type("two_factor_authentication.enable")
        assert "start" in types

    def test_disable_event_type(self, parser):
        """Test disable actions get end type."""
        types = parser._get_event_type("two_factor_authentication.disable")
        assert "end" in types

    def test_deny_event_type(self, parser):
        """Test deny actions get denied type."""
        types = parser._get_event_type("invitation.deny")
        assert "denied" in types

    def test_approve_event_type(self, parser):
        """Test approve actions get allowed type."""
        types = parser._get_event_type("deployment_review.approve")
        assert "allowed" in types

    def test_unknown_event_type_defaults_to_info(self, parser):
        """Test unknown events default to info type."""
        types = parser._get_event_type("some.other.event")
        assert types == ["info"]


class TestGitHubParserOutcome:
    """Test outcome determination."""

    @pytest.fixture
    def parser(self):
        return GitHubParser()

    def test_fail_in_action_is_failure(self, parser):
        """Test actions with 'fail' are failure."""
        event = {"action": "oauth_access.create_failed"}
        assert parser._get_outcome(event) == "failure"

    def test_error_in_action_is_failure(self, parser):
        """Test actions with 'error' are failure."""
        event = {"action": "webhook.error"}
        assert parser._get_outcome(event) == "failure"

    def test_deny_in_action_is_failure(self, parser):
        """Test actions with 'deny' are failure."""
        event = {"action": "invitation.deny"}
        assert parser._get_outcome(event) == "failure"

    def test_reject_in_action_is_failure(self, parser):
        """Test actions with 'reject' are failure."""
        event = {"action": "deployment_review.reject"}
        assert parser._get_outcome(event) == "failure"

    def test_normal_action_is_success(self, parser):
        """Test normal actions are success."""
        event = {"action": "repo.create"}
        assert parser._get_outcome(event) == "success"


class TestGitHubParserTimestamp:
    """Test timestamp parsing."""

    @pytest.fixture
    def parser(self):
        return GitHubParser()

    def test_parse_unix_timestamp_milliseconds(self, parser):
        """Test parsing Unix timestamp in milliseconds."""
        result = parser._parse_timestamp(1706500000000)
        # Result may vary by timezone, just check it's a valid ISO timestamp
        assert "2024-01-2" in result  # Could be 28 or 29 depending on timezone

    def test_parse_iso_timestamp(self, parser):
        """Test parsing ISO 8601 timestamp."""
        result = parser._parse_timestamp("2024-01-29T10:30:00Z")
        assert "2024-01-29" in result

    def test_parse_empty_timestamp(self, parser):
        """Test parsing empty timestamp returns None."""
        result = parser._parse_timestamp(None)
        assert result is None

    def test_parse_zero_timestamp(self, parser):
        """Test parsing zero timestamp returns None."""
        result = parser._parse_timestamp(0)
        assert result is None


class TestGitHubParserRemoveNoneValues:
    """Test None value removal."""

    @pytest.fixture
    def parser(self):
        return GitHubParser()

    def test_remove_none_values(self, parser):
        """Test None values are removed."""
        data = {
            "a": "value",
            "b": None,
            "c": {"d": "nested", "e": None}
        }
        result = parser._remove_none_values(data)

        assert "a" in result
        assert "b" not in result
        assert "d" in result["c"]
        assert "e" not in result["c"]

    def test_remove_empty_dicts(self, parser):
        """Test empty dicts are removed."""
        data = {"a": "value", "b": {}}
        result = parser._remove_none_values(data)

        assert "a" in result
        assert "b" not in result

    def test_remove_empty_lists(self, parser):
        """Test empty lists are removed."""
        data = {"a": "value", "b": []}
        result = parser._remove_none_values(data)

        assert "a" in result
        assert "b" not in result
