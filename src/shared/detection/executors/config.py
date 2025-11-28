"""Cloud provider configuration for query executors."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class CloudProvider(Enum):
    """Supported cloud providers."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


@dataclass
class AWSConfig:
    """AWS configuration for Athena."""

    database: str
    output_location: str
    region: str = "us-east-1"
    workgroup: str = "primary"


@dataclass
class GCPConfig:
    """GCP configuration for BigQuery."""

    project_id: str
    dataset: str
    location: str = "US"


@dataclass
class AzureConfig:
    """Azure configuration for Synapse."""

    server: str
    database: str
    username: Optional[str] = None
    password: Optional[str] = None
    use_managed_identity: bool = True


@dataclass
class CloudProviderConfig:
    """Multi-cloud configuration."""

    provider: CloudProvider
    aws: Optional[AWSConfig] = None
    gcp: Optional[GCPConfig] = None
    azure: Optional[AzureConfig] = None

    def validate(self) -> bool:
        """Validate that required config is present for the selected provider."""
        if self.provider == CloudProvider.AWS and self.aws is None:
            raise ValueError("AWS configuration required when provider is AWS")
        elif self.provider == CloudProvider.GCP and self.gcp is None:
            raise ValueError("GCP configuration required when provider is GCP")
        elif self.provider == CloudProvider.AZURE and self.azure is None:
            raise ValueError("Azure configuration required when provider is Azure")
        return True


def create_executor_from_config(config: CloudProviderConfig):
    """Create appropriate query executor based on configuration.

    Args:
        config: Cloud provider configuration

    Returns:
        QueryExecutor instance for the specified provider

    Raises:
        ValueError: If configuration is invalid
        ImportError: If required dependencies not installed
    """
    config.validate()

    if config.provider == CloudProvider.AWS:
        from .athena import AthenaQueryExecutor

        return AthenaQueryExecutor(
            database=config.aws.database,
            output_location=config.aws.output_location,
            region=config.aws.region,
            workgroup=config.aws.workgroup
        )

    elif config.provider == CloudProvider.GCP:
        from .bigquery import BigQueryExecutor

        return BigQueryExecutor(
            project_id=config.gcp.project_id,
            dataset=config.gcp.dataset,
            location=config.gcp.location
        )

    elif config.provider == CloudProvider.AZURE:
        from .synapse import SynapseExecutor

        return SynapseExecutor(
            server=config.azure.server,
            database=config.azure.database,
            username=config.azure.username,
            password=config.azure.password,
            use_managed_identity=config.azure.use_managed_identity
        )

    else:
        raise ValueError(f"Unsupported cloud provider: {config.provider}")
