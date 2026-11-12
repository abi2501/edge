from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv


def _load_env() -> None:
    explicit = os.getenv("EDGE_ENV_FILE")
    if explicit:
        load_dotenv(explicit, override=False)
        return

    # Load edge/.env when running from the project checkout.
    here = Path(__file__).resolve()
    edge_dir = here.parents[1]
    load_dotenv(edge_dir / ".env", override=False)


_load_env()


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return default if raw is None or raw == "" else int(raw)


@dataclass(frozen=True)
class Settings:
    device_id: str
    telemetry_db_path: str
    auth_db_path: str
    sync_state_db_path: str
    iothub_connection_string: str
    telemetry_poll_seconds: int
    telemetry_batch_size: int
    telemetry_retry_max_seconds: int
    rbac_api_base_url: str
    rbac_api_key: str
    rbac_sync_seconds: int
    rbac_http_timeout_seconds: int
    entra_tenant_id: str
    edge_public_client_id: str
    offline_auth_max_failed: int
    offline_auth_lock_seconds: int
    log_level: str


def get_settings(require_cloud: bool = True) -> Settings:
    iothub = os.getenv("IOTHUB_DEVICE_CONNECTION_STRING", "").strip()
    rbac_url = os.getenv("RBAC_API_BASE_URL", "").strip().rstrip("/")
    rbac_key = os.getenv("RBAC_API_KEY", "").strip()
    tenant = os.getenv("ENTRA_TENANT_ID", "").strip()
    public_client = os.getenv("EDGE_PUBLIC_CLIENT_ID", "").strip()

    if require_cloud:
        if not iothub:
            raise RuntimeError("IOTHUB_DEVICE_CONNECTION_STRING is not set")
        if not rbac_url or not rbac_key:
            raise RuntimeError("RBAC_API_BASE_URL and RBAC_API_KEY must be set")

    return Settings(
        device_id=_required("EDGE_DEVICE_ID"),
        telemetry_db_path=os.getenv("TELEMETRY_DB_PATH", "./data/telemetry.db"),
        auth_db_path=os.getenv("AUTH_DB_PATH", "./data/auth_cache.db"),
        sync_state_db_path=os.getenv("SYNC_STATE_DB_PATH", "./data/sync_state.db"),
        iothub_connection_string=iothub,
        telemetry_poll_seconds=_int("TELEMETRY_POLL_SECONDS", 5),
        telemetry_batch_size=_int("TELEMETRY_BATCH_SIZE", 100),
        telemetry_retry_max_seconds=_int("TELEMETRY_RETRY_MAX_SECONDS", 300),
        rbac_api_base_url=rbac_url,
        rbac_api_key=rbac_key,
        rbac_sync_seconds=_int("RBAC_SYNC_SECONDS", 300),
        rbac_http_timeout_seconds=_int("RBAC_HTTP_TIMEOUT_SECONDS", 20),
        entra_tenant_id=tenant,
        edge_public_client_id=public_client,
        offline_auth_max_failed=_int("OFFLINE_AUTH_MAX_FAILED", 5),
        offline_auth_lock_seconds=_int("OFFLINE_AUTH_LOCK_SECONDS", 300),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )
