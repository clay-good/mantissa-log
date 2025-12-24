"""Identity event mappers for each supported provider."""

from .base_mapper import BaseIdentityMapper
from .okta_mapper import OktaIdentityMapper
from .azure_mapper import AzureIdentityMapper
from .google_workspace_mapper import GoogleWorkspaceIdentityMapper
from .duo_mapper import DuoIdentityMapper
from .microsoft365_mapper import Microsoft365IdentityMapper

__all__ = [
    "BaseIdentityMapper",
    "OktaIdentityMapper",
    "AzureIdentityMapper",
    "GoogleWorkspaceIdentityMapper",
    "DuoIdentityMapper",
    "Microsoft365IdentityMapper",
]
