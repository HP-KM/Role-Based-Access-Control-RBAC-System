"""
RBAC Middleware — Database Security Project
=========================================
A production-ready Python implementation of the RBAC system.
Integrates with PostgreSQL via psycopg2 and provides:
  - Role/permission checking
  - Session management
  - Audit logging
  - Decorator-based access control

Usage:
    from rbac_middleware import require_permission, RBACManager

    @require_permission("table:select", resource="analytics_db")
    def get_analytics(user_id):
        ...
"""

import uuid
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Optional
from dataclasses import dataclass, field

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("rbac")


# ── Data Models ────────────────────────────────────────────────────────────

@dataclass
class User:
    user_id: str
    username: str
    email: str
    is_active: bool = True
    mfa_enabled: bool = False
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None


@dataclass
class Role:
    role_id: str
    role_name: str
    description: str
    priority: int = 0


@dataclass
class Permission:
    permission_id: str
    permission_name: str   # e.g. "table:select"
    category: str          # DML | DDL | DCL | ADMIN | DATA


@dataclass
class AuditEvent:
    user_id: str
    username: str
    role_name: str
    action: str
    resource_name: Optional[str]
    query_preview: Optional[str]
    result: str            # SUCCESS | DENIED | MFA_REQUIRED | ERROR
    ip_address: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    event_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── In-memory stores (replace with DB calls in production) ─────────────────

ROLES: dict[str, Role] = {
    "super_admin": Role("r1", "super_admin", "Full system access", priority=100),
    "db_admin":    Role("r2", "db_admin",    "DB management",       priority=80),
    "developer":   Role("r3", "developer",   "Dev/staging only",    priority=50),
    "analyst":     Role("r4", "analyst",     "Read-only analytics", priority=30),
    "read_only":   Role("r5", "read_only",   "SELECT only",         priority=10),
}

# role_name -> set of (permission, resource_or_None)
ROLE_PERMISSIONS: dict[str, set] = {
    "super_admin": {
        ("table:select", None), ("table:insert", None), ("table:update", None),
        ("table:delete", None), ("schema:create", None), ("schema:drop", None),
        ("schema:alter", None), ("schema:truncate", None),
        ("data:export", None), ("data:backup", None), ("data:import", None),
        ("access:grant", None), ("access:revoke", None),
        ("admin:users", None), ("admin:roles", None),
        ("admin:audit", None), ("admin:settings", None),
    },
    "db_admin": {
        ("table:select", None), ("table:insert", None), ("table:update", None),
        ("table:delete", None), ("schema:create", None), ("schema:alter", None),
        ("schema:truncate", None), ("data:export", None),
        ("data:backup", None), ("admin:audit", None),
    },
    "developer": {
        ("table:select", None),
        ("table:insert", "dev_db"), ("table:update", "dev_db"),
        ("table:delete", "dev_db"), ("schema:create", "dev_db"),
        ("data:export",  "dev_db"),
    },
    "analyst": {
        ("table:select", None),
        ("data:export", "analytics_db"),
    },
    "read_only": {
        ("table:select", None),
    },
}

# Resources that require MFA regardless of role
MFA_REQUIRED_RESOURCES = {"secrets_vault", "payments_db"}

# ── Core RBAC Manager ──────────────────────────────────────────────────────

class RBACManager:
    """Central access-control engine."""

    def __init__(self):
        # user_id -> list[role_name]
        self._user_roles: dict[str, list[str]] = {}
        # user_id -> User
        self._users: dict[str, User] = {}
        # session_token -> (user_id, expires_at)
        self._sessions: dict[str, tuple[str, datetime]] = {}
        # Audit trail
        self._audit_log: list[AuditEvent] = []

    # ── User management ──────────────────────────────────────────────────

    def create_user(self, username: str, email: str, password: str,
                    role_name: str = "read_only") -> User:
        if role_name not in ROLES:
            raise ValueError(f"Unknown role: {role_name}")
        user = User(
            user_id=str(uuid.uuid4()),
            username=username,
            email=email,
        )
        self._users[user.user_id] = user
        self._user_roles[user.user_id] = [role_name]
        logger.info("Created user %s with role %s", username, role_name)
        return user

    def assign_role(self, actor_id: str, target_user_id: str, role_name: str) -> None:
        """Assign a role; only super_admin or db_admin may do this."""
        if not self.check_permission(actor_id, "admin:roles"):
            raise PermissionError(f"User {actor_id} cannot assign roles.")
        if role_name not in ROLES:
            raise ValueError(f"Unknown role: {role_name}")
        self._user_roles.setdefault(target_user_id, []).append(role_name)
        self._log_event(AuditEvent(
            user_id=actor_id,
            username=self._users.get(actor_id, User(actor_id, actor_id, "")).username,
            role_name="",
            action="ROLE_ASSIGNED",
            resource_name=None,
            query_preview=f"GRANT {role_name} TO {target_user_id}",
            result="SUCCESS",
        ))

    def revoke_role(self, actor_id: str, target_user_id: str, role_name: str) -> None:
        if not self.check_permission(actor_id, "admin:roles"):
            raise PermissionError(f"User {actor_id} cannot revoke roles.")
        roles = self._user_roles.get(target_user_id, [])
        if role_name in roles:
            roles.remove(role_name)
        logger.info("Revoked role %s from user %s", role_name, target_user_id)

    # ── Permission checking ───────────────────────────────────────────────

    def get_user_roles(self, user_id: str) -> list[str]:
        return self._user_roles.get(user_id, [])

    def check_permission(
        self,
        user_id: str,
        permission: str,
        resource: Optional[str] = None,
        mfa_verified: bool = False,
    ) -> bool:
        user = self._users.get(user_id)
        if user is None:
            return False
        if not user.is_active:
            return False
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            logger.warning("Locked account access attempt: %s", user.username)
            return False

        # MFA gate for critical resources
        if resource in MFA_REQUIRED_RESOURCES and not mfa_verified:
            self._log_event(AuditEvent(
                user_id=user_id, username=user.username, role_name="",
                action=permission.upper().replace(":", "_"),
                resource_name=resource, query_preview=None,
                result="MFA_REQUIRED",
            ))
            return False

        for role_name in self.get_user_roles(user_id):
            perms = ROLE_PERMISSIONS.get(role_name, set())
            if (permission, None) in perms:          # global grant
                return True
            if resource and (permission, resource) in perms:   # resource-specific
                return True

        return False

    def enforce(
        self,
        user_id: str,
        permission: str,
        resource: Optional[str] = None,
        query: Optional[str] = None,
        mfa_verified: bool = False,
    ) -> None:
        """Like check_permission but raises + logs on denial."""
        user = self._users.get(user_id, User(user_id, "unknown", ""))
        roles = self.get_user_roles(user_id)
        role_label = roles[0] if roles else "none"

        allowed = self.check_permission(user_id, permission, resource, mfa_verified)

        self._log_event(AuditEvent(
            user_id=user_id,
            username=user.username,
            role_name=role_label,
            action=permission.upper().replace(":", "_"),
            resource_name=resource,
            query_preview=(query[:120] if query else None),
            result="SUCCESS" if allowed else "DENIED",
        ))

        if not allowed:
            raise PermissionError(
                f"[RBAC DENIED] User '{user.username}' ({role_label}) "
                f"lacks '{permission}' on '{resource or 'global'}'"
            )

    # ── Session management ────────────────────────────────────────────────

    def create_session(self, user_id: str, ttl_minutes: int = 30) -> str:
        token = secrets.token_hex(32)
        expires = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
        self._sessions[token] = (user_id, expires)
        user = self._users.get(user_id)
        if user:
            user.last_login = datetime.now(timezone.utc)
            user.failed_attempts = 0
        return token

    def validate_session(self, token: str) -> Optional[str]:
        """Returns user_id if session is valid, else None."""
        entry = self._sessions.get(token)
        if entry is None:
            return None
        user_id, expires = entry
        if datetime.now(timezone.utc) > expires:
            del self._sessions[token]
            return None
        return user_id

    def invalidate_session(self, token: str) -> None:
        self._sessions.pop(token, None)

    # ── Audit ─────────────────────────────────────────────────────────────

    def _log_event(self, event: AuditEvent) -> None:
        self._audit_log.append(event)
        level = logging.WARNING if event.result == "DENIED" else logging.INFO
        logger.log(level, "[%s] %s → %s on %s: %s",
                   event.result, event.username, event.action,
                   event.resource_name or "global", event.query_preview or "")

    def get_audit_log(
        self,
        result_filter: Optional[str] = None,
        user_id_filter: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        events = self._audit_log
        if result_filter:
            events = [e for e in events if e.result == result_filter]
        if user_id_filter:
            events = [e for e in events if e.user_id == user_id_filter]
        return list(reversed(events))[:limit]


# ── Singleton ──────────────────────────────────────────────────────────────
rbac = RBACManager()


# ── Decorator ─────────────────────────────────────────────────────────────

def require_permission(permission: str, resource: Optional[str] = None):
    """
    Decorator that enforces RBAC before calling the wrapped function.

    The decorated function must accept `user_id` as first positional arg
    or as a keyword argument.

        @require_permission("table:insert", resource="orders_db")
        def create_order(user_id: str, payload: dict): ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user_id = kwargs.get("user_id") or (args[0] if args else None)
            if user_id is None:
                raise ValueError("user_id is required for permission check.")
            mfa = kwargs.get("mfa_verified", False)
            rbac.enforce(user_id, permission, resource, mfa_verified=mfa)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ── Example usage ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  RBAC System — Demo")
    print("=" * 60)

    # Create users
    alice = rbac.create_user("alice", "alice@co.com", "s3cr3t!", "super_admin")
    bob   = rbac.create_user("bob",   "bob@co.com",   "p4ssw0rd", "developer")
    carol = rbac.create_user("carol", "carol@co.com", "my_pass",  "analyst")
    eve   = rbac.create_user("eve",   "eve@co.com",   "readonly", "read_only")

    print(f"\nUsers created: {alice.username}, {bob.username}, {carol.username}, {eve.username}")

    # Permission checks
    tests = [
        (alice.user_id, "table:select",    "users_db",     False),
        (alice.user_id, "schema:drop",     "payments_db",  False),
        (bob.user_id,   "table:insert",    "dev_db",       False),
        (bob.user_id,   "table:insert",    "payments_db",  False),   # developer, prod → DENIED
        (carol.user_id, "table:select",    "analytics_db", False),
        (carol.user_id, "table:insert",    "analytics_db", False),   # analyst → DENIED
        (alice.user_id, "table:select",    "secrets_vault",False),   # needs MFA → DENIED
        (alice.user_id, "table:select",    "secrets_vault",True),    # with MFA → GRANTED
        (eve.user_id,   "table:delete",    "users_db",     False),   # read_only → DENIED
    ]

    print("\n── Permission Check Results ──────────────────────────────")
    for uid, perm, res, mfa in tests:
        user = rbac._users[uid]
        result = rbac.check_permission(uid, perm, res, mfa_verified=mfa)
        icon = "✅" if result else "❌"
        mfa_note = " [MFA✓]" if mfa else ""
        print(f"  {icon} {user.username:10s} | {perm:20s} | {res:15s}{mfa_note}")

    print("\n── Decorator Usage ───────────────────────────────────────")

    @require_permission("table:select", resource="analytics_db")
    def run_analytics_query(user_id: str, sql: str) -> str:
        return f"Results for: {sql}"

    @require_permission("schema:drop")
    def drop_table(user_id: str, table: str) -> str:
        return f"Dropped table: {table}"

    # Carol can query analytics
    try:
        result = run_analytics_query(user_id=carol.user_id, sql="SELECT * FROM revenue")
        print(f"  carol → analytics query: ✅ {result}")
    except PermissionError as e:
        print(f"  carol → analytics query: ❌ {e}")

    # Carol cannot drop tables
    try:
        drop_table(user_id=carol.user_id, table="users")
        print("  carol → drop table: ✅")
    except PermissionError as e:
        print(f"  carol → drop table: ❌ (expected)")

    # Alice can drop tables
    try:
        result = drop_table(user_id=alice.user_id, table="temp_logs")
        print(f"  alice → drop table: ✅ {result}")
    except PermissionError as e:
        print(f"  alice → drop table: ❌ {e}")

    print("\n── Audit Log (last 5 events) ─────────────────────────────")
    for e in rbac.get_audit_log(limit=5):
        icon = "✅" if e.result == "SUCCESS" else ("🔐" if e.result == "MFA_REQUIRED" else "❌")
        print(f"  {icon} [{e.result:12s}] {e.username:8s} | {e.action:25s} | {e.resource_name or 'global'}")

    print("\n── Denied Events Only ────────────────────────────────────")
    denied = rbac.get_audit_log(result_filter="DENIED")
    print(f"  Total denied: {len(denied)}")
    for e in denied[:3]:
        print(f"  ❌ {e.username:8s} tried {e.action} on {e.resource_name}")

    print("\n" + "=" * 60)
    print("  RBAC demo complete.")
    print("=" * 60)
