"""Tests for cloud provider configuration and factory."""

import pytest
from src.shared.detection.executors.config import (
    CloudProvider,
    AWSConfig,
    GCPConfig,
    AzureConfig,
    CloudProviderConfig,
    create_executor_from_config
)
from src.shared.detection.executors.athena import AthenaQueryExecutor
from src.shared.detection.executors.bigquery import BigQueryExecutor
from src.shared.detection.executors.synapse import SynapseExecutor


class TestCloudProvider:
    """Tests for CloudProvider enum."""

    def test_cloud_provider_values(self):
        """Test CloudProvider enum values."""
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.GCP.value == "gcp"
        assert CloudProvider.AZURE.value == "azure"

    def test_cloud_provider_members(self):
        """Test CloudProvider enum members."""
        providers = [p.value for p in CloudProvider]
        assert "aws" in providers
        assert "gcp" in providers
        assert "azure" in providers


class TestAWSConfig:
    """Tests for AWS configuration."""

    def test_aws_config_with_defaults(self):
        """Test AWS config with default values."""
        config = AWSConfig(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        assert config.database == 'test_db'
        assert config.output_location == 's3://bucket/results/'
        assert config.region == 'us-east-1'
        assert config.workgroup == 'primary'

    def test_aws_config_with_custom_values(self):
        """Test AWS config with custom values."""
        config = AWSConfig(
            database='prod_db',
            output_location='s3://prod-bucket/output/',
            region='us-west-2',
            workgroup='prod-workgroup'
        )

        assert config.database == 'prod_db'
        assert config.region == 'us-west-2'
        assert config.workgroup == 'prod-workgroup'


class TestGCPConfig:
    """Tests for GCP configuration."""

    def test_gcp_config_with_defaults(self):
        """Test GCP config with default values."""
        config = GCPConfig(
            project_id='test-project',
            dataset='test_dataset'
        )

        assert config.project_id == 'test-project'
        assert config.dataset == 'test_dataset'
        assert config.location == 'US'

    def test_gcp_config_with_custom_location(self):
        """Test GCP config with custom location."""
        config = GCPConfig(
            project_id='eu-project',
            dataset='eu_dataset',
            location='EU'
        )

        assert config.location == 'EU'


class TestAzureConfig:
    """Tests for Azure configuration."""

    def test_azure_config_with_managed_identity(self):
        """Test Azure config with managed identity (default)."""
        config = AzureConfig(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        assert config.server == 'test-synapse.sql.azuresynapse.net'
        assert config.database == 'test_db'
        assert config.username is None
        assert config.password is None
        assert config.use_managed_identity is True

    def test_azure_config_with_sql_auth(self):
        """Test Azure config with SQL authentication."""
        config = AzureConfig(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db',
            username='admin',
            password='password123',
            use_managed_identity=False
        )

        assert config.username == 'admin'
        assert config.password == 'password123'
        assert config.use_managed_identity is False


class TestCloudProviderConfig:
    """Tests for CloudProviderConfig."""

    def test_cloud_provider_config_aws(self):
        """Test cloud provider config for AWS."""
        aws_config = AWSConfig(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        config = CloudProviderConfig(
            provider=CloudProvider.AWS,
            aws=aws_config
        )

        assert config.provider == CloudProvider.AWS
        assert config.aws == aws_config
        assert config.gcp is None
        assert config.azure is None

    def test_cloud_provider_config_gcp(self):
        """Test cloud provider config for GCP."""
        gcp_config = GCPConfig(
            project_id='test-project',
            dataset='test_dataset'
        )

        config = CloudProviderConfig(
            provider=CloudProvider.GCP,
            gcp=gcp_config
        )

        assert config.provider == CloudProvider.GCP
        assert config.gcp == gcp_config
        assert config.aws is None
        assert config.azure is None

    def test_cloud_provider_config_azure(self):
        """Test cloud provider config for Azure."""
        azure_config = AzureConfig(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        config = CloudProviderConfig(
            provider=CloudProvider.AZURE,
            azure=azure_config
        )

        assert config.provider == CloudProvider.AZURE
        assert config.azure == azure_config
        assert config.aws is None
        assert config.gcp is None


class TestCloudProviderConfigValidation:
    """Tests for CloudProviderConfig validation."""

    def test_validate_aws_success(self):
        """Test successful AWS config validation."""
        config = CloudProviderConfig(
            provider=CloudProvider.AWS,
            aws=AWSConfig(
                database='test_db',
                output_location='s3://bucket/results/'
            )
        )

        assert config.validate() is True

    def test_validate_aws_missing_config(self):
        """Test AWS validation failure when config is missing."""
        config = CloudProviderConfig(
            provider=CloudProvider.AWS
        )

        with pytest.raises(ValueError) as exc_info:
            config.validate()

        assert "AWS configuration required" in str(exc_info.value)

    def test_validate_gcp_success(self):
        """Test successful GCP config validation."""
        config = CloudProviderConfig(
            provider=CloudProvider.GCP,
            gcp=GCPConfig(
                project_id='test-project',
                dataset='test_dataset'
            )
        )

        assert config.validate() is True

    def test_validate_gcp_missing_config(self):
        """Test GCP validation failure when config is missing."""
        config = CloudProviderConfig(
            provider=CloudProvider.GCP
        )

        with pytest.raises(ValueError) as exc_info:
            config.validate()

        assert "GCP configuration required" in str(exc_info.value)

    def test_validate_azure_success(self):
        """Test successful Azure config validation."""
        config = CloudProviderConfig(
            provider=CloudProvider.AZURE,
            azure=AzureConfig(
                server='test-synapse.sql.azuresynapse.net',
                database='test_db'
            )
        )

        assert config.validate() is True

    def test_validate_azure_missing_config(self):
        """Test Azure validation failure when config is missing."""
        config = CloudProviderConfig(
            provider=CloudProvider.AZURE
        )

        with pytest.raises(ValueError) as exc_info:
            config.validate()

        assert "Azure configuration required" in str(exc_info.value)


class TestCreateExecutorFromConfig:
    """Tests for executor factory function."""

    def test_create_athena_executor(self):
        """Test creating Athena executor from config."""
        config = CloudProviderConfig(
            provider=CloudProvider.AWS,
            aws=AWSConfig(
                database='test_db',
                output_location='s3://bucket/results/',
                region='us-west-2',
                workgroup='test-workgroup'
            )
        )

        executor = create_executor_from_config(config)

        assert isinstance(executor, AthenaQueryExecutor)
        assert executor.database == 'test_db'
        assert executor.output_location == 's3://bucket/results/'
        assert executor.region == 'us-west-2'
        assert executor.workgroup == 'test-workgroup'

    def test_create_bigquery_executor(self):
        """Test creating BigQuery executor from config."""
        config = CloudProviderConfig(
            provider=CloudProvider.GCP,
            gcp=GCPConfig(
                project_id='test-project',
                dataset='test_dataset',
                location='EU'
            )
        )

        executor = create_executor_from_config(config)

        assert isinstance(executor, BigQueryExecutor)
        assert executor.project_id == 'test-project'
        assert executor.dataset == 'test_dataset'
        assert executor.location == 'EU'

    def test_create_synapse_executor(self):
        """Test creating Synapse executor from config."""
        config = CloudProviderConfig(
            provider=CloudProvider.AZURE,
            azure=AzureConfig(
                server='test-synapse.sql.azuresynapse.net',
                database='test_db',
                username='admin',
                password='password123',
                use_managed_identity=False
            )
        )

        executor = create_executor_from_config(config)

        assert isinstance(executor, SynapseExecutor)
        assert executor.server == 'test-synapse.sql.azuresynapse.net'
        assert executor.database == 'test_db'
        assert executor.username == 'admin'
        assert executor.password == 'password123'
        assert executor.use_managed_identity is False

    def test_create_executor_invalid_config(self):
        """Test creating executor with invalid config."""
        config = CloudProviderConfig(
            provider=CloudProvider.AWS
            # Missing AWS config
        )

        with pytest.raises(ValueError):
            create_executor_from_config(config)

    def test_create_executor_unsupported_provider(self):
        """Test creating executor with unsupported provider."""
        # This test uses a mock to simulate an unsupported provider
        config = CloudProviderConfig(
            provider=CloudProvider.AWS,
            aws=AWSConfig(
                database='test_db',
                output_location='s3://bucket/results/'
            )
        )

        # Modify provider to invalid value (for testing)
        config.provider = "unsupported"

        with pytest.raises(ValueError) as exc_info:
            create_executor_from_config(config)

        assert "Unsupported cloud provider" in str(exc_info.value)
