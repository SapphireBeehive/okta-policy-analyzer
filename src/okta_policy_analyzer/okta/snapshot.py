"""Tenant snapshot: everything the analyzer needs, fetched once and stored as plain JSON.

A snapshot is a directory::

    manifest.json                 org URL, timestamp, tool version, per-collection counts
    policies.json                 all policies (every type) with their rules embedded under "_rules"
    policy_mappings.json          {policyId: [app ids]} for ACCESS_POLICY (from /mappings or app links)
    apps.json                     applications (id, label, name, status, signOnMode, _links.accessPolicy)
    groups.json                   groups (+ _embedded.stats when available)
    group_rules.json              group rules
    zones.json                    network zones
    device_assurances.json        device assurance policies
    authenticators.json           authenticators, each with "_methods" embedded when available
    user_types.json               user types
    idps.json                     identity providers
    users.json                    (optional, --with-users) users with "_groupIds" embedded

The same content can also be stored as one JSON file (``Snapshot.save_file`` / ``Snapshot.load``).
Snapshots contain no secrets, so they are safe to check into a repo as test fixtures.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .client import OktaAPIError, OktaClient

log = logging.getLogger(__name__)

POLICY_TYPES: tuple[str, ...] = (
    "ACCESS_POLICY",
    "OKTA_SIGN_ON",
    "MFA_ENROLL",
    "PASSWORD",
    "PROFILE_ENROLLMENT",
    "IDP_DISCOVERY",
)

COLLECTIONS: tuple[str, ...] = (
    "policies",
    "policy_mappings",
    "apps",
    "groups",
    "group_rules",
    "zones",
    "device_assurances",
    "authenticators",
    "user_types",
    "idps",
    "users",
)


@dataclass
class SnapshotManifest:
    org_url: str
    fetched_at: str
    tool_version: str
    counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    with_users: bool = False
    pipeline: str = (
        ""  # "idx" (Identity Engine) or "v1" (Classic Engine), from /.well-known/okta-organization
    )
    org_id: str = ""


@dataclass
class Snapshot:
    manifest: SnapshotManifest
    policies: list[dict[str, Any]] = field(default_factory=list)
    policy_mappings: dict[str, list[str]] = field(default_factory=dict)
    apps: list[dict[str, Any]] = field(default_factory=list)
    groups: list[dict[str, Any]] = field(default_factory=list)
    group_rules: list[dict[str, Any]] = field(default_factory=list)
    zones: list[dict[str, Any]] = field(default_factory=list)
    device_assurances: list[dict[str, Any]] = field(default_factory=list)
    authenticators: list[dict[str, Any]] = field(default_factory=list)
    user_types: list[dict[str, Any]] = field(default_factory=list)
    idps: list[dict[str, Any]] = field(default_factory=list)
    users: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------ persistence
    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"manifest": asdict(self.manifest)}
        for name in COLLECTIONS:
            d[name] = getattr(self, name)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Snapshot:
        man = d.get("manifest") or {}
        manifest = SnapshotManifest(
            org_url=man.get("org_url", ""),
            fetched_at=man.get("fetched_at", ""),
            tool_version=man.get("tool_version", ""),
            counts=man.get("counts", {}),
            warnings=man.get("warnings", []),
            with_users=man.get("with_users", False),
            pipeline=man.get("pipeline", ""),
            org_id=man.get("org_id", ""),
        )
        snap = cls(manifest=manifest)
        for name in COLLECTIONS:
            if name in d and d[name] is not None:
                setattr(snap, name, d[name])
        snap.manifest.counts = snap._counts()
        return snap

    def _counts(self) -> dict[str, int]:
        return {name: len(getattr(self, name)) for name in COLLECTIONS}

    def save_dir(self, path: str | Path) -> None:
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        self.manifest.counts = self._counts()
        (p / "manifest.json").write_text(_dumps(asdict(self.manifest)))
        for name in COLLECTIONS:
            (p / f"{name}.json").write_text(_dumps(getattr(self, name)))

    def save_file(self, path: str | Path) -> None:
        self.manifest.counts = self._counts()
        Path(path).write_text(_dumps(self.to_dict()))

    @classmethod
    def load(cls, path: str | Path) -> Snapshot:
        """Load from a snapshot directory or a single-file snapshot."""
        p = Path(path)
        if p.is_dir():
            d: dict[str, Any] = {"manifest": json.loads((p / "manifest.json").read_text())}
            for name in COLLECTIONS:
                f = p / f"{name}.json"
                if f.exists():
                    d[name] = json.loads(f.read_text())
            return cls.from_dict(d)
        return cls.from_dict(json.loads(p.read_text()))

    # ------------------------------------------------------------------ convenience
    def policies_of_type(self, ptype: str) -> list[dict[str, Any]]:
        return [p for p in self.policies if p.get("type") == ptype]


def _dumps(obj: Any) -> str:
    return json.dumps(obj, indent=1, sort_keys=False, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------- fetching


def fetch_snapshot(
    client: OktaClient,
    *,
    with_users: bool = False,
    policy_types: tuple[str, ...] = POLICY_TYPES,
    include_inactive_policies: bool = True,
    progress: Callable[[str], None] | None = None,
    tool_version: str = "",
) -> Snapshot:
    """Pull a complete read-only snapshot of the org's policy configuration.

    Every failure of an *optional* collection (e.g. device assurance on an org without the feature) is recorded
    in ``manifest.warnings`` instead of aborting, so that a partial snapshot is still analyzable and the report
    can say what is missing.
    """
    say = progress or (lambda msg: log.info("%s", msg))
    warnings: list[str] = []
    snap = Snapshot(
        manifest=SnapshotManifest(
            org_url=client.org_url,
            fetched_at=datetime.now(UTC).isoformat(timespec="seconds"),
            tool_version=tool_version,
            with_users=with_users,
        )
    )

    def optional(name: str, fn: Callable[[], Any], default: Any) -> Any:
        try:
            say(f"fetching {name}")
            return fn()
        except OktaAPIError as e:
            msg = f"{name}: {e}"
            log.warning(msg)
            warnings.append(msg)
            return default

    # --- engine detection (public endpoint) -----------------------------------------------------
    well_known = optional("org metadata", lambda: client.get("/.well-known/okta-organization"), {}) or {}
    snap.manifest.pipeline = str(well_known.get("pipeline") or "")
    snap.manifest.org_id = str(well_known.get("id") or "")
    if snap.manifest.pipeline == "v1":
        raise OktaAPIError(
            0,
            client.org_url,
            {
                "errorSummary": "this org runs Okta Classic Engine (pipeline v1); authentication policies exist only on Identity Engine"
            },
        )

    # --- policies (required) -------------------------------------------------------------------
    for ptype in policy_types:
        params: dict[str, Any] = {"type": ptype, "expand": "rules"}
        if not include_inactive_policies:
            params["status"] = "ACTIVE"
        try:
            say(f"fetching policies type={ptype}")
            pols = client.list_all("/api/v1/policies", params)
        except OktaAPIError as e:
            if ptype in ("ACCESS_POLICY", "OKTA_SIGN_ON"):
                raise
            warnings.append(f"policies type={ptype}: {e}")
            continue
        for pol in pols:
            rules = _embedded_rules(pol)
            if rules is None:
                try:
                    rules = client.list_all(f"/api/v1/policies/{pol['id']}/rules")
                except OktaAPIError as e:
                    warnings.append(f"rules for policy {pol.get('id')}: {e}")
                    rules = []
            pol["_rules"] = rules
            emb = pol.pop("_embedded", None) or {}
            if emb.get("resourceType"):
                pol["_resourceType"] = emb["resourceType"]  # APP or END_USER_ACCOUNT_MANAGEMENT
            snap.policies.append(pol)

    # --- apps and access-policy mappings ---------------------------------------------------------
    snap.apps = optional("apps", lambda: client.list_all("/api/v1/apps", {"limit": 200}), [])
    mappings: dict[str, list[str]] = {}
    for app in snap.apps:
        href = ((app.get("_links") or {}).get("accessPolicy") or {}).get("href")
        if href:
            pid = href.rstrip("/").rsplit("/", 1)[-1]
            mappings.setdefault(pid, []).append(app["id"])
    if not snap.apps:
        # Fall back to the policy mappings endpoint when apps could not be listed.
        for pol in snap.policies_of_type("ACCESS_POLICY"):
            maps = optional(
                f"mappings for {pol['id']}",
                lambda pol=pol: client.list_all(f"/api/v1/policies/{pol['id']}/mappings"),
                [],
            )
            ids = [_mapping_app_id(m) for m in maps if isinstance(m, dict)]
            mappings[pol["id"]] = [i for i in ids if i]
    snap.policy_mappings = mappings

    # --- who: groups, group rules, user types ----------------------------------------------------
    snap.groups = optional(
        "groups", lambda: client.list_all("/api/v1/groups", {"limit": 200, "expand": "stats"}), []
    )
    snap.group_rules = optional(
        "group rules", lambda: client.list_all("/api/v1/groups/rules", {"limit": 200}), []
    )
    snap.user_types = optional("user types", lambda: client.get("/api/v1/meta/types/user"), [])

    # --- context: zones, device assurance, idps -------------------------------------------------
    snap.zones = optional("network zones", lambda: client.list_all("/api/v1/zones", {"limit": 200}), [])
    snap.device_assurances = optional(
        "device assurance policies", lambda: client.get("/api/v1/device-assurances"), []
    )
    snap.idps = optional("identity providers", lambda: client.list_all("/api/v1/idps", {"limit": 200}), [])

    # --- authenticators and their methods ---------------------------------------------------------
    snap.authenticators = optional("authenticators", lambda: client.get("/api/v1/authenticators"), [])
    for auth in snap.authenticators:
        methods = optional(
            f"methods for authenticator {auth.get('key')}",
            lambda auth=auth: client.get(f"/api/v1/authenticators/{auth['id']}/methods"),
            None,
        )
        if methods is not None:
            auth["_methods"] = methods

    # --- optional concrete mode: users with their group ids ----------------------------------------
    if with_users:
        users = optional("users", lambda: client.list_all("/api/v1/users", {"limit": 200}), [])
        for i, u in enumerate(users):
            if i % 100 == 0:
                say(f"fetching group memberships {i}/{len(users)}")
            groups = optional(
                f"groups of user {u.get('id')}",
                lambda u=u: client.list_all(f"/api/v1/users/{u['id']}/groups", {"limit": 200}),
                [],
            )
            u["_groupIds"] = [g["id"] for g in groups]
        snap.users = users

    snap.manifest.warnings = warnings
    snap.manifest.counts = snap._counts()
    return snap


def _mapping_app_id(mapping: dict[str, Any]) -> str | None:
    """Policy mappings carry the app only as ``_links.application.href``."""
    href = ((mapping.get("_links") or {}).get("application") or {}).get("href")
    if href:
        return href.rstrip("/").rsplit("/", 1)[-1]
    return mapping.get("resourceId")


def _embedded_rules(policy: dict[str, Any]) -> list[dict[str, Any]] | None:
    emb = policy.get("_embedded")
    if isinstance(emb, dict) and isinstance(emb.get("rules"), list):
        return emb["rules"]
    return None
