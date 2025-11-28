"""
Query Executor Factory for Multi-Cloud Support

Creates the appropriate query executor based on cloud provider configuration.
"""

import os
from typing import Optional
from .base import QueryExecutor
from .athena import AthenaQueryExecutor


def create_executor(
    cloud_provider: Optional[str] = None,
    **kwargs
) -> QueryExecutor:
    """
    Create appropriate query executor for cloud provider.

    Args:
        cloud_provider: Cloud provider (aws, gcp, azure)
        **kwargs: Provider-specific configuration

    Returns:
        QueryExecutor instance for the cloud provider

    Raises:
        ValueError: If cloud provider is unsupported
        ImportError: If required dependencies are missing
    """
    # Get cloud provider from environment if not specified
    if cloud_provider is None:
        cloud_provider = os.environ.get('CLOUD_PROVIDER', 'aws').lower()

    if cloud_provider == 'aws':
        return _create_aws_executor(**kwargs)
    elif cloud_provider == 'gcp':
        return _create_gcp_executor(**kwargs)
    elif cloud_provider == 'azure':
        return _create_azure_executor(**kwargs)
    else:
        raise ValueError(
            f"Unsupported cloud provider: {cloud_provider}. "
            f"Must be 'aws', 'gcp', or 'azure'"
        )


def _create_aws_executor(**kwargs) -> AthenaQueryExecutor:
    """Create AWS Athena executor"""
    database = kwargs.get('database') or os.environ.get('ATHENA_DATABASE')
    output_location = kwargs.get('output_location') or os.environ.get('ATHENA_OUTPUT_LOCATION')
    region = kwargs.get('region') or os.environ.get('AWS_REGION', 'us-east-1')
    workgroup = kwargs.get('workgroup') or os.environ.get('ATHENA_WORKGROUP')

    if not database:
        raise ValueError("ATHENA_DATABASE must be specified")
    if not output_location:
        raise ValueError("ATHENA_OUTPUT_LOCATION must be specified")

    return AthenaQueryExecutor(
        database=database,
        output_location=output_location,
        region=region,
        workgroup=workgroup
    )


def _create_gcp_executor(**kwargs):
    """Create GCP BigQuery executor"""
    try:
        from ..gcp.bigquery.executor import BigQueryExecutor
    except ImportError:
        raise ImportError(
            "BigQuery executor not available. "
            "Ensure google-cloud-bigquery is installed."
        )

    project_id = kwargs.get('project_id') or os.environ.get('GCP_PROJECT_ID')
    dataset_id = kwargs.get('dataset_id') or os.environ.get('BIGQUERY_DATASET')
    credentials_path = kwargs.get('credentials_path') or os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')

    if not project_id:
        raise ValueError("GCP_PROJECT_ID must be specified")
    if not dataset_id:
        raise ValueError("BIGQUERY_DATASET must be specified")

    return BigQueryExecutor(
        project_id=project_id,
        dataset_id=dataset_id,
        credentials_path=credentials_path
    )


def _create_azure_executor(**kwargs):
    """Create Azure Synapse executor"""
    try:
        from ..azure.synapse.executor import SynapseExecutor
    except ImportError:
        raise ImportError(
            "Synapse executor not available. "
            "Ensure azure-identity and pyodbc are installed."
        )

    workspace_name = kwargs.get('workspace_name') or os.environ.get('SYNAPSE_WORKSPACE_NAME')
    server_name = kwargs.get('server_name') or os.environ.get('SYNAPSE_SERVER_NAME')
    database_name = kwargs.get('database_name') or os.environ.get('SYNAPSE_DATABASE_NAME')
    use_serverless = kwargs.get('use_serverless', True)

    if not workspace_name and not server_name:
        raise ValueError("Either SYNAPSE_WORKSPACE_NAME or SYNAPSE_SERVER_NAME must be specified")
    if not database_name:
        raise ValueError("SYNAPSE_DATABASE_NAME must be specified")

    return SynapseExecutor(
        workspace_name=workspace_name,
        server_name=server_name,
        database_name=database_name,
        use_serverless=use_serverless
    )


def get_supported_providers() -> list:
    """
    Get list of supported cloud providers.

    Returns:
        List of supported provider names
    """
    return ['aws', 'gcp', 'azure']


def is_provider_available(cloud_provider: str) -> bool:
    """
    Check if cloud provider dependencies are available.

    Args:
        cloud_provider: Cloud provider name

    Returns:
        True if dependencies are installed
    """
    if cloud_provider == 'aws':
        try:
            import boto3
            return True
        except ImportError:
            return False

    elif cloud_provider == 'gcp':
        try:
            from google.cloud import bigquery
            return True
        except ImportError:
            return False

    elif cloud_provider == 'azure':
        try:
            import pyodbc
            from azure.identity import DefaultAzureCredential
            return True
        except ImportError:
            return False

    return False
