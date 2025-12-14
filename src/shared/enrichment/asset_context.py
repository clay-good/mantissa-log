"""Asset Context Enrichment Service.

Provides asset context from AWS, Azure, and GCP native cloud services.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AssetContext:
    """Asset context information from cloud provider."""

    asset_id: str
    asset_type: str  # ec2, vm, gce, rds, s3, etc.
    cloud_provider: str  # aws, azure, gcp

    # Basic info
    name: Optional[str] = None
    display_name: Optional[str] = None
    description: Optional[str] = None
    region: Optional[str] = None
    zone: Optional[str] = None

    # Ownership
    owner: Optional[str] = None
    owner_email: Optional[str] = None
    team: Optional[str] = None
    cost_center: Optional[str] = None

    # Classification
    environment: Optional[str] = None  # production, staging, development
    classification: Optional[str] = None  # public, internal, confidential
    criticality: Optional[str] = None  # critical, high, medium, low

    # Status
    state: str = "unknown"  # running, stopped, terminated, etc.
    is_public: bool = False
    last_seen: Optional[str] = None

    # Network
    private_ip: Optional[str] = None
    public_ip: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    security_groups: List[str] = field(default_factory=list)

    # Compliance
    compliance_status: Optional[str] = None  # compliant, non-compliant, not-applicable
    compliance_findings: List[str] = field(default_factory=list)

    # Tags
    tags: Dict[str, str] = field(default_factory=dict)

    # Metadata
    created_at: Optional[str] = None
    source: str = "unknown"
    cached: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "cloud_provider": self.cloud_provider,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "region": self.region,
            "zone": self.zone,
            "owner": self.owner,
            "owner_email": self.owner_email,
            "team": self.team,
            "cost_center": self.cost_center,
            "environment": self.environment,
            "classification": self.classification,
            "criticality": self.criticality,
            "state": self.state,
            "is_public": self.is_public,
            "last_seen": self.last_seen,
            "private_ip": self.private_ip,
            "public_ip": self.public_ip,
            "vpc_id": self.vpc_id,
            "subnet_id": self.subnet_id,
            "security_groups": self.security_groups,
            "compliance_status": self.compliance_status,
            "compliance_findings": self.compliance_findings,
            "tags": self.tags,
            "created_at": self.created_at,
            "source": self.source,
            "cached": self.cached,
            "error": self.error,
        }


class AssetContextCache:
    """In-memory cache for asset context."""

    def __init__(self, ttl_hours: int = 1, max_size: int = 5000):
        """Initialize cache."""
        self.ttl = timedelta(hours=ttl_hours)
        self.max_size = max_size
        self._cache: Dict[str, tuple] = {}

    def _make_key(self, asset_id: str, cloud_provider: str) -> str:
        """Generate cache key."""
        return f"{cloud_provider}:{asset_id}"

    def get(self, asset_id: str, cloud_provider: str) -> Optional[AssetContext]:
        """Get cached asset context."""
        key = self._make_key(asset_id, cloud_provider)
        if key in self._cache:
            result, timestamp = self._cache[key]
            if datetime.utcnow() - timestamp < self.ttl:
                result.cached = True
                return result
            else:
                del self._cache[key]
        return None

    def put(self, asset_context: AssetContext) -> None:
        """Cache asset context."""
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

        key = self._make_key(asset_context.asset_id, asset_context.cloud_provider)
        self._cache[key] = (asset_context, datetime.utcnow())

    def clear(self) -> None:
        """Clear cache."""
        self._cache.clear()


class AssetContextService:
    """Asset context service supporting multiple cloud providers."""

    # Common tag keys for ownership and classification
    OWNER_TAGS = ["Owner", "owner", "Team", "team", "Contact", "contact"]
    ENV_TAGS = ["Environment", "environment", "Env", "env", "Stage", "stage"]
    CLASSIFICATION_TAGS = ["Classification", "classification", "DataClassification", "Sensitivity"]
    CRITICALITY_TAGS = ["Criticality", "criticality", "Priority", "priority"]

    def __init__(
        self,
        # AWS
        aws_region: Optional[str] = None,
        # Azure
        azure_subscription_id: Optional[str] = None,
        # GCP
        gcp_project_id: Optional[str] = None,
        # Cache
        cache_ttl_hours: int = 1,
    ):
        """Initialize asset context service.

        Args:
            aws_region: AWS region for API calls
            azure_subscription_id: Azure subscription ID
            gcp_project_id: GCP project ID
            cache_ttl_hours: Cache TTL in hours
        """
        self.aws_region = aws_region or os.environ.get("AWS_REGION", "us-east-1")
        self.azure_subscription_id = azure_subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
        self.gcp_project_id = gcp_project_id or os.environ.get("GCP_PROJECT_ID")

        self.cache = AssetContextCache(ttl_hours=cache_ttl_hours)

    def get_asset(self, asset_id: str, cloud_provider: Optional[str] = None) -> AssetContext:
        """Get asset context.

        Args:
            asset_id: Asset identifier (instance ID, resource ID, etc.)
            cloud_provider: Cloud provider (aws, azure, gcp)
                           If None, will try to detect from asset_id format

        Returns:
            AssetContext
        """
        # Detect provider from ID format if not specified
        if not cloud_provider:
            cloud_provider = self._detect_provider(asset_id)

        if cloud_provider == "aws":
            return self._get_aws_asset(asset_id)
        elif cloud_provider == "azure":
            return self._get_azure_asset(asset_id)
        elif cloud_provider == "gcp":
            return self._get_gcp_asset(asset_id)
        else:
            return AssetContext(
                asset_id=asset_id,
                asset_type="unknown",
                cloud_provider="unknown",
                error="Could not determine cloud provider",
            )

    def _detect_provider(self, asset_id: str) -> str:
        """Detect cloud provider from asset ID format."""
        # AWS formats: i-xxx, arn:aws:xxx
        if asset_id.startswith("i-") or asset_id.startswith("arn:aws:"):
            return "aws"
        # Azure format: /subscriptions/xxx
        if asset_id.startswith("/subscriptions/"):
            return "azure"
        # GCP format: projects/xxx
        if asset_id.startswith("projects/") or "googleapis.com" in asset_id:
            return "gcp"
        return "unknown"

    def _get_aws_asset(self, asset_id: str) -> AssetContext:
        """Get asset from AWS."""
        # Check cache
        cached = self.cache.get(asset_id, "aws")
        if cached:
            return cached

        result = AssetContext(
            asset_id=asset_id,
            asset_type="unknown",
            cloud_provider="aws",
            source="aws",
        )

        try:
            import boto3

            # Detect asset type and get details
            if asset_id.startswith("i-"):
                result = self._get_aws_ec2_instance(asset_id)
            elif "arn:aws:rds:" in asset_id or asset_id.startswith("db-"):
                result = self._get_aws_rds_instance(asset_id)
            elif "arn:aws:s3:" in asset_id or not asset_id.startswith("arn:"):
                # Could be S3 bucket name
                result = self._get_aws_s3_bucket(asset_id)
            elif "arn:aws:lambda:" in asset_id:
                result = self._get_aws_lambda_function(asset_id)
            else:
                result.error = f"Unknown AWS asset type: {asset_id}"

            if not result.error:
                self.cache.put(result)
            return result

        except ImportError:
            result.error = "boto3 package required for AWS asset lookups"
            return result
        except Exception as e:
            logger.debug(f"AWS asset lookup failed for {asset_id}: {e}")
            result.error = str(e)
            return result

    def _get_aws_ec2_instance(self, instance_id: str) -> AssetContext:
        """Get EC2 instance details."""
        import boto3

        ec2 = boto3.client("ec2", region_name=self.aws_region)
        response = ec2.describe_instances(InstanceIds=[instance_id])

        if not response.get("Reservations"):
            return AssetContext(
                asset_id=instance_id,
                asset_type="ec2",
                cloud_provider="aws",
                error="Instance not found",
            )

        instance = response["Reservations"][0]["Instances"][0]
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}

        result = AssetContext(
            asset_id=instance_id,
            asset_type="ec2",
            cloud_provider="aws",
            name=tags.get("Name"),
            region=self.aws_region,
            zone=instance.get("Placement", {}).get("AvailabilityZone"),
            state=instance.get("State", {}).get("Name", "unknown"),
            private_ip=instance.get("PrivateIpAddress"),
            public_ip=instance.get("PublicIpAddress"),
            vpc_id=instance.get("VpcId"),
            subnet_id=instance.get("SubnetId"),
            security_groups=[sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
            is_public=bool(instance.get("PublicIpAddress")),
            created_at=instance.get("LaunchTime").isoformat() if instance.get("LaunchTime") else None,
            tags=tags,
            source="aws_ec2",
        )

        # Extract ownership and classification from tags
        self._extract_tags_metadata(result, tags)

        return result

    def _get_aws_rds_instance(self, db_identifier: str) -> AssetContext:
        """Get RDS instance details."""
        import boto3

        rds = boto3.client("rds", region_name=self.aws_region)

        # Extract identifier from ARN if needed
        if "arn:aws:rds:" in db_identifier:
            db_identifier = db_identifier.split(":")[-1]

        response = rds.describe_db_instances(DBInstanceIdentifier=db_identifier)

        if not response.get("DBInstances"):
            return AssetContext(
                asset_id=db_identifier,
                asset_type="rds",
                cloud_provider="aws",
                error="RDS instance not found",
            )

        db = response["DBInstances"][0]
        tags_response = rds.list_tags_for_resource(ResourceName=db["DBInstanceArn"])
        tags = {t["Key"]: t["Value"] for t in tags_response.get("TagList", [])}

        result = AssetContext(
            asset_id=db_identifier,
            asset_type="rds",
            cloud_provider="aws",
            name=db.get("DBInstanceIdentifier"),
            region=self.aws_region,
            zone=db.get("AvailabilityZone"),
            state=db.get("DBInstanceStatus", "unknown"),
            vpc_id=db.get("DBSubnetGroup", {}).get("VpcId"),
            is_public=db.get("PubliclyAccessible", False),
            created_at=db.get("InstanceCreateTime").isoformat() if db.get("InstanceCreateTime") else None,
            tags=tags,
            source="aws_rds",
        )

        self._extract_tags_metadata(result, tags)
        return result

    def _get_aws_s3_bucket(self, bucket_name: str) -> AssetContext:
        """Get S3 bucket details."""
        import boto3

        s3 = boto3.client("s3")

        # Remove arn prefix if present
        if "arn:aws:s3:::" in bucket_name:
            bucket_name = bucket_name.split(":::")[-1]

        result = AssetContext(
            asset_id=bucket_name,
            asset_type="s3",
            cloud_provider="aws",
            name=bucket_name,
            source="aws_s3",
        )

        try:
            # Get bucket location
            location = s3.get_bucket_location(Bucket=bucket_name)
            result.region = location.get("LocationConstraint") or "us-east-1"

            # Get tags
            try:
                tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
                tags = {t["Key"]: t["Value"] for t in tags_response.get("TagSet", [])}
                result.tags = tags
                self._extract_tags_metadata(result, tags)
            except Exception:
                pass

            # Check if public
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                        result.is_public = True
                        break
            except Exception:
                pass

            result.state = "available"
            return result

        except Exception as e:
            result.error = str(e)
            return result

    def _get_aws_lambda_function(self, function_name: str) -> AssetContext:
        """Get Lambda function details."""
        import boto3

        lambda_client = boto3.client("lambda", region_name=self.aws_region)

        # Extract function name from ARN if needed
        if "arn:aws:lambda:" in function_name:
            function_name = function_name.split(":")[-1]

        try:
            response = lambda_client.get_function(FunctionName=function_name)
            config = response.get("Configuration", {})
            tags = response.get("Tags", {})

            result = AssetContext(
                asset_id=function_name,
                asset_type="lambda",
                cloud_provider="aws",
                name=config.get("FunctionName"),
                description=config.get("Description"),
                region=self.aws_region,
                state=config.get("State", "unknown"),
                vpc_id=config.get("VpcConfig", {}).get("VpcId"),
                subnet_id=",".join(config.get("VpcConfig", {}).get("SubnetIds", [])),
                security_groups=config.get("VpcConfig", {}).get("SecurityGroupIds", []),
                created_at=config.get("LastModified"),
                tags=tags,
                source="aws_lambda",
            )

            self._extract_tags_metadata(result, tags)
            return result

        except Exception as e:
            return AssetContext(
                asset_id=function_name,
                asset_type="lambda",
                cloud_provider="aws",
                error=str(e),
            )

    def _get_azure_asset(self, resource_id: str) -> AssetContext:
        """Get asset from Azure Resource Graph."""
        # Check cache
        cached = self.cache.get(resource_id, "azure")
        if cached:
            return cached

        result = AssetContext(
            asset_id=resource_id,
            asset_type="unknown",
            cloud_provider="azure",
            source="azure",
        )

        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resourcegraph import ResourceGraphClient
            from azure.mgmt.resourcegraph.models import QueryRequest

            credential = DefaultAzureCredential()
            client = ResourceGraphClient(credential)

            # Query Azure Resource Graph
            query = f"""
            Resources
            | where id =~ '{resource_id}'
            | project id, name, type, location, resourceGroup, subscriptionId, tags, properties
            """

            request = QueryRequest(
                subscriptions=[self.azure_subscription_id] if self.azure_subscription_id else [],
                query=query,
            )

            response = client.resources(request)

            if not response.data:
                result.error = "Resource not found"
                return result

            resource = response.data[0]
            tags = resource.get("tags", {}) or {}

            # Determine asset type
            resource_type = resource.get("type", "").lower()
            if "virtualmachines" in resource_type:
                result.asset_type = "vm"
            elif "storageaccounts" in resource_type:
                result.asset_type = "storage"
            elif "databases" in resource_type or "sql" in resource_type:
                result.asset_type = "database"
            else:
                result.asset_type = resource_type.split("/")[-1] if "/" in resource_type else resource_type

            result.name = resource.get("name")
            result.region = resource.get("location")
            result.tags = tags

            # Extract properties
            properties = resource.get("properties", {})
            if "networkProfile" in properties:
                network = properties["networkProfile"]
                if "networkInterfaces" in network and network["networkInterfaces"]:
                    result.vpc_id = network["networkInterfaces"][0].get("id", "").split("/")[4] if "/" in network["networkInterfaces"][0].get("id", "") else None

            self._extract_tags_metadata(result, tags)

            if not result.error:
                self.cache.put(result)
            return result

        except ImportError:
            result.error = "azure-identity and azure-mgmt-resourcegraph packages required"
            return result
        except Exception as e:
            logger.debug(f"Azure asset lookup failed for {resource_id}: {e}")
            result.error = str(e)
            return result

    def _get_gcp_asset(self, resource_name: str) -> AssetContext:
        """Get asset from GCP Cloud Asset Inventory."""
        # Check cache
        cached = self.cache.get(resource_name, "gcp")
        if cached:
            return cached

        result = AssetContext(
            asset_id=resource_name,
            asset_type="unknown",
            cloud_provider="gcp",
            source="gcp",
        )

        try:
            from google.cloud import asset_v1

            client = asset_v1.AssetServiceClient()

            # Search for the asset
            scope = f"projects/{self.gcp_project_id}"
            query = f"name:{resource_name}"

            response = client.search_all_resources(
                scope=scope,
                query=query,
                page_size=1,
            )

            resources = list(response)
            if not resources:
                result.error = "Resource not found"
                return result

            resource = resources[0]
            labels = dict(resource.labels) if resource.labels else {}

            # Determine asset type from resource type
            resource_type = resource.asset_type.lower()
            if "instance" in resource_type and "compute" in resource_type:
                result.asset_type = "gce"
            elif "bucket" in resource_type:
                result.asset_type = "gcs"
            elif "dataset" in resource_type:
                result.asset_type = "bigquery"
            else:
                result.asset_type = resource_type.split("/")[-1] if "/" in resource_type else resource_type

            result.name = resource.display_name or resource.name.split("/")[-1]
            result.region = resource.location
            result.tags = labels

            self._extract_tags_metadata(result, labels)

            if not result.error:
                self.cache.put(result)
            return result

        except ImportError:
            result.error = "google-cloud-asset package required"
            return result
        except Exception as e:
            logger.debug(f"GCP asset lookup failed for {resource_name}: {e}")
            result.error = str(e)
            return result

    def _extract_tags_metadata(self, result: AssetContext, tags: Dict[str, str]) -> None:
        """Extract ownership and classification metadata from tags."""
        # Owner
        for tag in self.OWNER_TAGS:
            if tag in tags:
                value = tags[tag]
                if "@" in value:
                    result.owner_email = value
                else:
                    result.owner = value
                break

        # Environment
        for tag in self.ENV_TAGS:
            if tag in tags:
                result.environment = tags[tag].lower()
                break

        # Classification
        for tag in self.CLASSIFICATION_TAGS:
            if tag in tags:
                result.classification = tags[tag].lower()
                break

        # Criticality
        for tag in self.CRITICALITY_TAGS:
            if tag in tags:
                result.criticality = tags[tag].lower()
                break

        # Team / Cost Center
        if "Team" in tags or "team" in tags:
            result.team = tags.get("Team") or tags.get("team")
        if "CostCenter" in tags or "cost-center" in tags:
            result.cost_center = tags.get("CostCenter") or tags.get("cost-center")


def get_asset_context(asset_id: str, cloud_provider: Optional[str] = None, **kwargs) -> AssetContext:
    """Convenience function to get asset context.

    Args:
        asset_id: Asset identifier
        cloud_provider: Optional cloud provider
        **kwargs: Arguments passed to AssetContextService

    Returns:
        AssetContext
    """
    service = AssetContextService(**kwargs)
    return service.get_asset(asset_id, cloud_provider=cloud_provider)
