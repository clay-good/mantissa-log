"""
Secret store interface for SaaS collectors.

Collectors need to hold OAuth refresh tokens, service-account JSON, and Entra
client secrets. Each deployment target (local dev, AWS, GCP, Azure) wants to
keep those somewhere different. This module exposes an ABC and ships two
zero-dependency backends (env vars, JSON file). Cloud-native backends are
documented as TODOs and added in their own module per cloud to keep imports
optional.

Key shape:
    f"{source}/{tenant_id}/{secret_name}"
e.g.  ``gws/acme.com/service_account_json``
      ``m365/contoso/client_secret``
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional


class SecretStore(ABC):
    """Read/write opaque string secrets keyed by namespaced strings."""

    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Return the secret value, or None if not present."""

    @abstractmethod
    def put(self, key: str, value: str) -> None:
        """Persist a secret value."""

    def require(self, key: str) -> str:
        value = self.get(key)
        if value is None:
            raise KeyError(f"secret not found: {key}")
        return value


class EnvSecretStore(SecretStore):
    """Secrets sourced from environment variables.

    The key ``gws/acme.com/refresh_token`` maps to env var
    ``MANTISSA_SECRET_GWS__ACME_COM__REFRESH_TOKEN`` (uppercased, ``/`` and
    non-alnum replaced with ``__``). Read-only outside of the process env.
    """

    PREFIX = "MANTISSA_SECRET_"

    def _envify(self, key: str) -> str:
        out = []
        for ch in key:
            if ch.isalnum():
                out.append(ch.upper())
            else:
                out.append("_")
        return self.PREFIX + "".join(out)

    def get(self, key: str) -> Optional[str]:
        return os.environ.get(self._envify(key))

    def put(self, key: str, value: str) -> None:
        os.environ[self._envify(key)] = value


class LocalFileSecretStore(SecretStore):
    """JSON-file-backed secret store. Intended for local dev and tests only.

    Stores a single JSON object at ``path``. File mode is 0600 on write.
    Production deployments should use a cloud secret manager backend.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text() or "{}")

    def _save(self, data: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True))
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get(self, key: str) -> Optional[str]:
        return self._load().get(key)

    def put(self, key: str, value: str) -> None:
        data = self._load()
        data[key] = value
        self._save(data)


# TODO: AWSSecretsManagerStore in saas_secrets_aws.py
# TODO: GCPSecretManagerStore in saas_secrets_gcp.py
# TODO: AzureKeyVaultStore in saas_secrets_azure.py
# Each backend imports its own SDK and is selected by config. Keeping them
# in separate modules avoids forcing every deployment to install all three.
