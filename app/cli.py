from __future__ import annotations

import argparse
import getpass
import json
import random
import time
from pathlib import Path

from .config import get_settings
from . import db
from .entra_auth import interactive_device_login
from .rbac_client import fetch_snapshot
from .security import set_offline_secret, verify_offline_secret


def cmd_init(_args) -> None:
    s = get_settings(require_cloud=False)
    db.init_telemetry_db(s.telemetry_db_path)
    db.init_auth_db(s.auth_db_path)
    db.init_sync_state_db(s.sync_state_db_path)
    print(f"Initialized {s.telemetry_db_path}")
    print(f"Initialized {s.auth_db_path}")
    print(f"Initialized {s.sync_state_db_path}")


def cmd_generate(args) -> None:
    s = get_settings(require_cloud=False)
    for i in range(args.count):
        payload = {
            "temperatureC": round(random.uniform(20.0, 70.0), 2),
            "pressureKPa": round(random.uniform(95.0, 115.0), 2),
            "machineState": random.choice(["IDLE", "RUNNING", "RUNNING", "RUNNING"]),
            "sequence": i + 1,
        }
        severity = "WARNING" if payload["temperatureC"] > 60 else "INFO"
        row_id = db.add_telemetry(s.telemetry_db_path, "measurement", severity, payload)
        print(f"Created telemetry row {row_id}: {json.dumps(payload)}")
        if args.interval > 0 and i < args.count - 1:
            time.sleep(args.interval)


def cmd_status(_args) -> None:
    s = get_settings(require_cloud=False)
    db.init_telemetry_db(s.telemetry_db_path)
    db.init_auth_db(s.auth_db_path)
    db.init_sync_state_db(s.sync_state_db_path)
    cp = db.telemetry_checkpoint(s.sync_state_db_path)
    with db.connect(s.telemetry_db_path) as conn:
        max_id = conn.execute("SELECT COALESCE(MAX(id),0) FROM telemetry_events").fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()[0]
    print(f"Device ID          : {s.device_id}")
    print(f"Telemetry rows     : {total}")
    print(f"Max source ID      : {max_id}")
    print(f"Last synced ID     : {cp}")
    print(f"Approx pending     : {max(0, int(max_id) - cp)}")
    print(f"Auth sync state    : {json.dumps(db.auth_sync_state(s.auth_db_path), indent=2)}")


def cmd_rbac_sync(_args) -> None:
    s = get_settings(require_cloud=True)
    snapshot = fetch_snapshot(s.rbac_api_base_url, s.rbac_api_key, s.device_id, s.rbac_http_timeout_seconds)
    db.replace_authorization_snapshot(s.auth_db_path, snapshot)
    print(f"RBAC synchronized. Version={snapshot['version']} users={len(snapshot['users'])}")


def cmd_users(_args) -> None:
    s = get_settings(require_cloud=False)
    users = db.list_users(s.auth_db_path)
    if not users:
        print("No cached users. Run 'rbac-sync' while online first.")
        return
    for user in users:
        print(
            f"{user['username']} | enabled={user['enabled']} | roles={','.join(user['roles']) or '-'} | "
            f"validUntil={user['validUntilUtc']}"
        )


def cmd_enroll(_args) -> None:
    s = get_settings(require_cloud=False)
    # This step intentionally requires live Entra authentication. It does not collect the Entra password.
    me = interactive_device_login(s.entra_tenant_id, s.edge_public_client_id)
    oid = me["id"]
    username = me.get("userPrincipalName") or ""
    cached = db.get_user_by_oid(s.auth_db_path, oid)
    if cached is None or not bool(cached["enabled"]):
        raise RuntimeError(
            "Authenticated Entra user is not enabled in the local RBAC cache. "
            "Run rbac-sync and verify the user has an App Role assignment."
        )

    print(f"Authenticated as {username} ({me.get('displayName','')})")
    print("Create a device-local offline PIN/passphrase. This is NOT your Microsoft password.")
    one = getpass.getpass("Offline PIN/passphrase: ")
    two = getpass.getpass("Repeat: ")
    if one != two:
        raise RuntimeError("Values do not match")
    set_offline_secret(s.auth_db_path, oid, one)
    print("Offline credential enrolled successfully.")


def cmd_login(args) -> None:
    s = get_settings(require_cloud=False)
    username = args.username or input("Username: ").strip()
    secret = getpass.getpass("Offline PIN/passphrase: ")
    ok, message, roles = verify_offline_secret(
        s.auth_db_path,
        username,
        secret,
        s.offline_auth_max_failed,
        s.offline_auth_lock_seconds,
    )
    print(message)
    if ok:
        print("Roles:", ", ".join(roles) if roles else "(none)")
        # Example authorization decisions that a PyQt UI would apply to buttons/pages.
        permissions = {
            "view_status": bool(roles),
            "start_operation": any(r in roles for r in ("Operator", "Supervisor", "DeviceAdmin")),
            "change_settings": any(r in roles for r in ("Supervisor", "ServiceEngineer", "DeviceAdmin")),
            "service_tools": any(r in roles for r in ("ServiceEngineer", "DeviceAdmin")),
            "user_admin": "DeviceAdmin" in roles,
        }
        print("Permissions:")
        for key, allowed in permissions.items():
            print(f"  {'ALLOW' if allowed else 'DENY ':5} {key}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WSL/Raspberry Pi edge-device POC utility")
    sub = p.add_subparsers(dest="command", required=True)

    x = sub.add_parser("init", help="Create local SQLite databases")
    x.set_defaults(func=cmd_init)

    x = sub.add_parser("generate", help="Generate telemetry rows in local SQLite")
    x.add_argument("--count", type=int, default=1)
    x.add_argument("--interval", type=float, default=0.0)
    x.set_defaults(func=cmd_generate)

    x = sub.add_parser("status", help="Show local telemetry/RBAC state")
    x.set_defaults(func=cmd_status)

    x = sub.add_parser("rbac-sync", help="Synchronize Entra users/roles into local auth SQLite now")
    x.set_defaults(func=cmd_rbac_sync)

    x = sub.add_parser("users", help="List locally cached authorized users and roles")
    x.set_defaults(func=cmd_users)

    x = sub.add_parser("enroll", help="Authenticate online with Entra and create a local offline PIN/passphrase")
    x.set_defaults(func=cmd_enroll)

    x = sub.add_parser("login", help="Perform an offline login using SQLite")
    x.add_argument("--username")
    x.set_defaults(func=cmd_login)
    return p


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
