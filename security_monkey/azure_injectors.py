"""Azure misconfiguration injectors.

Each injector weakens the secure baseline created by terraform/azure/. Auth uses
DefaultAzureCredential, so `az login` (or an env service principal) is enough — we never
handle secrets directly.

Injectors are constructed lazily (SDK clients are only created when needed) so that
`--dry-run` and `--list` work without any cloud credentials or network calls.
"""
from __future__ import annotations

import os
import uuid
from functools import cached_property

from .base import Injector, InjectionRecord
from .config import AzureConfig

# Priority of the inbound ALLOW rule the network injector adds. Lower than the baseline
# deny (4000) so it actually takes effect.
_OPEN_RULE_NAME = "seclab-injected-open-inbound"
_OPEN_RULE_PRIORITY = 100
_OPEN_SINGLEPORT_RULE_NAME = "seclab-injected-open-singleport"
_OPEN_SINGLEPORT_PRIORITY = 101
_PUBLIC_CONTAINER = "labdata"


class _AzureClients:
    """Lazily-built Azure SDK clients sharing one credential."""

    def __init__(self, cfg: AzureConfig):
        self.cfg = cfg

    @cached_property
    def _credential(self):
        from azure.identity import DefaultAzureCredential

        return DefaultAzureCredential()

    @cached_property
    def network(self):
        from azure.mgmt.network import NetworkManagementClient

        return NetworkManagementClient(self._credential, self.cfg.subscription_id)

    @cached_property
    def storage(self):
        from azure.mgmt.storage import StorageManagementClient

        return StorageManagementClient(self._credential, self.cfg.subscription_id)

    @cached_property
    def authorization(self):
        from azure.mgmt.authorization import AuthorizationManagementClient

        return AuthorizationManagementClient(self._credential, self.cfg.subscription_id)


# --------------------------------------------------------------------------- #
# 1. Network exposure — open an NSG inbound rule to 0.0.0.0/0
# --------------------------------------------------------------------------- #
class NsgOpenInjector(Injector):
    key = "azure-nsg-open"
    misconfig_class = "network-exposure"
    cloud = "azure"
    description = "Adds an NSG inbound rule allowing ANY source (0.0.0.0/0) to reach SSH/RDP."

    def __init__(self, cfg: AzureConfig, clients: _AzureClients):
        self.cfg = cfg
        self.clients = clients

    def inject(self) -> InjectionRecord:
        self.cfg.assert_in_scope(self.cfg.resource_group)
        rule = {
            "protocol": "Tcp",
            "source_port_range": "*",
            "destination_port_ranges": ["22", "3389"],
            "source_address_prefix": "0.0.0.0/0",
            "destination_address_prefix": "*",
            "access": "Allow",
            "priority": _OPEN_RULE_PRIORITY,
            "direction": "Inbound",
            "description": "INTENTIONAL lab misconfig injected by Security Monkey.",
        }
        poller = self.clients.network.security_rules.begin_create_or_update(
            self.cfg.resource_group, self.cfg.nsg_name, _OPEN_RULE_NAME, rule
        )
        poller.result()
        return InjectionRecord(
            injector_key=self.key,
            cloud=self.cloud,
            misconfig_class=self.misconfig_class,
            target=f"{self.cfg.nsg_name}/{_OPEN_RULE_NAME}",
            detail={"rule_name": _OPEN_RULE_NAME, "nsg": self.cfg.nsg_name},
        )

    def revert(self, record: InjectionRecord) -> None:
        rule_name = record.detail.get("rule_name", _OPEN_RULE_NAME)
        poller = self.clients.network.security_rules.begin_delete(
            self.cfg.resource_group, self.cfg.nsg_name, rule_name
        )
        poller.result()


class NsgOpenSinglePortInjector(Injector):
    """Single-port variant of `azure-nsg-open`.

    Same real-world exposure (RDP 3389 open to 0.0.0.0/0), but the port is expressed via the
    SINGULAR `destination_port_range` field instead of the plural `destination_port_ranges`.
    Used to demonstrate a Prowler coverage gap: Prowler's Azure RDP/SSH internet-access checks
    inspect only the singular field, so they DETECT this variant but MISS the plural one.
    See results/detection-coverage-matrix.md (note 1).
    """

    key = "azure-nsg-open-singleport"
    misconfig_class = "network-exposure"
    cloud = "azure"
    description = "Opens RDP (3389) to 0.0.0.0/0 via destination_port_range (singular) — the Prowler-detectable variant."

    def __init__(self, cfg: AzureConfig, clients: _AzureClients):
        self.cfg = cfg
        self.clients = clients

    def inject(self) -> InjectionRecord:
        self.cfg.assert_in_scope(self.cfg.resource_group)
        rule = {
            "protocol": "Tcp",
            "source_port_range": "*",
            "destination_port_range": "3389",
            "source_address_prefix": "0.0.0.0/0",
            "destination_address_prefix": "*",
            "access": "Allow",
            "priority": _OPEN_SINGLEPORT_PRIORITY,
            "direction": "Inbound",
            "description": "INTENTIONAL lab misconfig injected by Security Monkey (single-port variant).",
        }
        poller = self.clients.network.security_rules.begin_create_or_update(
            self.cfg.resource_group, self.cfg.nsg_name, _OPEN_SINGLEPORT_RULE_NAME, rule
        )
        poller.result()
        return InjectionRecord(
            injector_key=self.key,
            cloud=self.cloud,
            misconfig_class=self.misconfig_class,
            target=f"{self.cfg.nsg_name}/{_OPEN_SINGLEPORT_RULE_NAME}",
            detail={"rule_name": _OPEN_SINGLEPORT_RULE_NAME, "nsg": self.cfg.nsg_name},
        )

    def revert(self, record: InjectionRecord) -> None:
        rule_name = record.detail.get("rule_name", _OPEN_SINGLEPORT_RULE_NAME)
        poller = self.clients.network.security_rules.begin_delete(
            self.cfg.resource_group, self.cfg.nsg_name, rule_name
        )
        poller.result()


# --------------------------------------------------------------------------- #
# 2. Public data — enable public blob access + a public container
# --------------------------------------------------------------------------- #
class StoragePublicInjector(Injector):
    key = "azure-storage-public"
    misconfig_class = "public-data"
    cloud = "azure"
    description = "Enables blob public access on the storage account and opens a container to anonymous read."

    def __init__(self, cfg: AzureConfig, clients: _AzureClients):
        self.cfg = cfg
        self.clients = clients

    def inject(self) -> InjectionRecord:
        self.cfg.assert_in_scope(self.cfg.resource_group)
        import time

        from azure.core.exceptions import HttpResponseError
        from azure.mgmt.storage.models import (
            BlobContainer,
            StorageAccountUpdateParameters,
        )

        # Step 1: allow public access at the account level (the Terraform baseline has it off).
        self.clients.storage.storage_accounts.update(
            self.cfg.resource_group,
            self.cfg.storage_account,
            StorageAccountUpdateParameters(allow_blob_public_access=True),
        )
        # Step 2: open the container to anonymous blob read. The account-level flag can take a
        # few seconds to propagate to the blob service, so retry on PublicAccessNotPermitted.
        for attempt in range(6):
            try:
                self.clients.storage.blob_containers.update(
                    self.cfg.resource_group,
                    self.cfg.storage_account,
                    _PUBLIC_CONTAINER,
                    BlobContainer(public_access="Blob"),
                )
                break
            except HttpResponseError as exc:
                if "PublicAccessNotPermitted" in str(exc) and attempt < 5:
                    time.sleep(5)
                    continue
                raise

        return InjectionRecord(
            injector_key=self.key,
            cloud=self.cloud,
            misconfig_class=self.misconfig_class,
            target=f"{self.cfg.storage_account}/{_PUBLIC_CONTAINER}",
            detail={"container": _PUBLIC_CONTAINER, "account": self.cfg.storage_account},
        )

    def revert(self, record: InjectionRecord) -> None:
        from azure.mgmt.storage.models import (
            BlobContainer,
            StorageAccountUpdateParameters,
        )

        container = record.detail.get("container", _PUBLIC_CONTAINER)
        # Restore container to private first, then lock the account back down.
        self.clients.storage.blob_containers.update(
            self.cfg.resource_group,
            self.cfg.storage_account,
            container,
            BlobContainer(public_access="None"),
        )
        self.clients.storage.storage_accounts.update(
            self.cfg.resource_group,
            self.cfg.storage_account,
            StorageAccountUpdateParameters(allow_blob_public_access=False),
        )


# --------------------------------------------------------------------------- #
# 3. Over-permissive identity — assign a broad RBAC role at the RG scope
# --------------------------------------------------------------------------- #
# Built-in role definition IDs (subscription-agnostic GUIDs).
_ROLE_IDS = {
    "Owner": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
}


class RbacBroadInjector(Injector):
    key = "azure-rbac-broad"
    misconfig_class = "over-permissive-identity"
    cloud = "azure"
    description = "Assigns a broad built-in role (default Contributor) at the lab RG scope to a test principal."

    def __init__(self, cfg: AzureConfig, clients: _AzureClients):
        self.cfg = cfg
        self.clients = clients
        # Principal to over-privilege. Supply a throwaway lab principal's object ID.
        self.principal_id = os.environ.get("SECLAB_AZURE_TEST_PRINCIPAL_ID", "").strip()
        self.role = os.environ.get("SECLAB_AZURE_BROAD_ROLE", "Contributor").strip()

    @property
    def _scope(self) -> str:
        return (
            f"/subscriptions/{self.cfg.subscription_id}"
            f"/resourceGroups/{self.cfg.resource_group}"
        )

    def inject(self) -> InjectionRecord:
        self.cfg.assert_in_scope(self.cfg.resource_group)
        if not self.principal_id:
            raise RuntimeError(
                "SECLAB_AZURE_TEST_PRINCIPAL_ID is not set. Provide the object ID of a "
                "throwaway lab principal to over-privilege (see README)."
            )
        role_id = _ROLE_IDS.get(self.role, _ROLE_IDS["Contributor"])
        role_definition_id = (
            f"/subscriptions/{self.cfg.subscription_id}"
            f"/providers/Microsoft.Authorization/roleDefinitions/{role_id}"
        )
        assignment_name = str(uuid.uuid4())
        # Flat keys — the SDK maps them onto the REST `properties.*` shape itself. Wrapping them
        # in an extra "properties" layer produces a MalformedRoleAssignmentRequest.
        params = {
            "role_definition_id": role_definition_id,
            "principal_id": self.principal_id,
            "principal_type": "ServicePrincipal",
        }
        # A freshly-created managed identity can take a few seconds to replicate into Entra ID,
        # so the role assignment may briefly fail with PrincipalNotFound — retry.
        import time

        from azure.core.exceptions import HttpResponseError

        for attempt in range(6):
            try:
                self.clients.authorization.role_assignments.create(
                    scope=self._scope,
                    role_assignment_name=assignment_name,
                    parameters=params,
                )
                break
            except HttpResponseError as exc:
                if "PrincipalNotFound" in str(exc) and attempt < 5:
                    time.sleep(5)
                    continue
                raise
        return InjectionRecord(
            injector_key=self.key,
            cloud=self.cloud,
            misconfig_class=self.misconfig_class,
            target=f"{self.cfg.resource_group} <- {self.role}",
            detail={
                "assignment_name": assignment_name,
                "scope": self._scope,
                "role": self.role,
                "principal_id": self.principal_id,
            },
        )

    def revert(self, record: InjectionRecord) -> None:
        scope = record.detail.get("scope", self._scope)
        assignment_name = record.detail["assignment_name"]
        self.clients.authorization.role_assignments.delete(
            scope=scope, role_assignment_name=assignment_name
        )


#: Injector classes, for metadata listing without needing cloud config.
INJECTOR_CLASSES: list[type[Injector]] = [
    NsgOpenInjector,
    NsgOpenSinglePortInjector,
    StoragePublicInjector,
    RbacBroadInjector,
]


def build_injectors(cfg: AzureConfig | None = None) -> list[Injector]:
    """Return all Azure injectors. Cheap: no cloud calls until inject/revert."""
    cfg = cfg or AzureConfig.from_env()
    clients = _AzureClients(cfg)
    return [cls(cfg, clients) for cls in INJECTOR_CLASSES]
