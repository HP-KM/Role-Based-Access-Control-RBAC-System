from __future__ import annotations

"""
Role-Based Access Control (RBAC) System
========================================
Core implementation: Users, Roles, Permissions, and access checks.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


# ── 1. PERMISSIONS ──────────────────────────────────────────────────────────
# A Permission is the finest unit of access — "what action on what resource"

@dataclass
class Permission:
    name: str          # e.g. "posts:read"
    description: str   # human-readable explanation

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return isinstance(other, Permission) and self.name == other.name

    def __repr__(self):
        return f"Permission({self.name!r})"


# ── 2. ROLES ────────────────────────────────────────────────────────────────
# A Role is a named collection of permissions assigned to users.

@dataclass
class Role:
    name: str
    description: str
    permissions: set[Permission] = field(default_factory=set)

    def add_permission(self, perm: Permission):
        self.permissions.add(perm)
        return self

    def remove_permission(self, perm: Permission):
        self.permissions.discard(perm)
        return self

    def has_permission(self, perm: Permission) -> bool:
        return perm in self.permissions

    def __repr__(self):
        perms = ", ".join(p.name for p in self.permissions)
        return f"Role({self.name!r}, permissions=[{perms}])"

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return isinstance(other, Role) and self.name == other.name


# ── 3. USERS ────────────────────────────────────────────────────────────────
# A User holds one or more Roles. Access is derived from those roles.

@dataclass
class User:
    id: int
    username: str
    email: str
    roles: set[Role] = field(default_factory=set)
    active: bool = True

    def assign_role(self, role: Role):
        self.roles.add(role)
        return self

    def revoke_role(self, role: Role):
        self.roles.discard(role)
        return self

    def can(self, permission: Permission) -> bool:
        """Return True if ANY of the user's roles grants this permission."""
        if not self.active:
            return False
        return any(role.has_permission(permission) for role in self.roles)

    def all_permissions(self) -> set[Permission]:
        result = set()
        for role in self.roles:
            result |= role.permissions
        return result

    def __repr__(self):
        role_names = ", ".join(r.name for r in self.roles)
        return f"User({self.username!r}, roles=[{role_names}])"


# ── 4. RBAC MANAGER ─────────────────────────────────────────────────────────
# Central registry; also logs every access attempt for auditing.

@dataclass
class AccessLog:
    timestamp: str
    user: str
    permission: str
    resource: str
    granted: bool
    reason: str


class RBACManager:
    def __init__(self):
        self.permissions: dict[str, Permission] = {}
        self.roles: dict[str, Role] = {}
        self.users: dict[int, User] = {}
        self._next_user_id = 1
        self.audit_log: list[AccessLog] = []

    # ── Permissions
    def create_permission(self, name: str, description: str) -> Permission:
        perm = Permission(name=name, description=description)
        self.permissions[name] = perm
        return perm

    def get_permission(self, name: str) -> Optional[Permission]:
        return self.permissions.get(name)

    # ── Roles
    def create_role(self, name: str, description: str) -> Role:
        role = Role(name=name, description=description)
        self.roles[name] = role
        return role

    def get_role(self, name: str) -> Optional[Role]:
        return self.roles.get(name)

    # ── Users
    def create_user(self, username: str, email: str) -> User:
        user = User(id=self._next_user_id, username=username, email=email)
        self.users[self._next_user_id] = user
        self._next_user_id += 1
        return user

    def get_user(self, user_id: int) -> Optional[User]:
        return self.users.get(user_id)

    # ── Access check (with audit logging)
    def check_access(self, user: User, permission_name: str, resource: str = "") -> bool:
        perm = self.permissions.get(permission_name)
        if perm is None:
            self._log(user.username, permission_name, resource, False, "Unknown permission")
            return False

        if not user.active:
            self._log(user.username, permission_name, resource, False, "User inactive")
            return False

        granted = user.can(perm)
        reason = "Role grants access" if granted else "No role grants this permission"
        self._log(user.username, permission_name, resource, granted, reason)
        return granted

    def _log(self, user: str, perm: str, resource: str, granted: bool, reason: str):
        self.audit_log.append(AccessLog(
            timestamp=datetime.now().isoformat(timespec="seconds"),
            user=user,
            permission=perm,
            resource=resource,
            granted=granted,
            reason=reason,
        ))


# ── 5. SAMPLE SETUP (Blog Platform) ─────────────────────────────────────────

def build_demo() -> RBACManager:
    rbac = RBACManager()

    # -- Permissions
    posts_read    = rbac.create_permission("posts:read",    "Read published posts")
    posts_write   = rbac.create_permission("posts:write",   "Create / edit own posts")
    posts_delete  = rbac.create_permission("posts:delete",  "Delete any post")
    users_read    = rbac.create_permission("users:read",    "View user profiles")
    users_manage  = rbac.create_permission("users:manage",  "Create / suspend users")
    settings_edit = rbac.create_permission("settings:edit", "Change site-wide settings")
    comments_mod  = rbac.create_permission("comments:mod",  "Moderate comments")

    # -- Roles
    viewer = rbac.create_role("Viewer", "Read-only access")
    viewer.add_permission(posts_read)

    author = rbac.create_role("Author", "Can write and read posts")
    author.add_permission(posts_read).add_permission(posts_write)

    moderator = rbac.create_role("Moderator", "Can moderate comments and read users")
    moderator.add_permission(posts_read).add_permission(comments_mod).add_permission(users_read)

    admin = rbac.create_role("Admin", "Full access")
    for p in [posts_read, posts_write, posts_delete,
              users_read, users_manage, settings_edit, comments_mod]:
        admin.add_permission(p)

    # -- Users
    alice = rbac.create_user("alice", "alice@example.com")
    alice.assign_role(admin)

    bob = rbac.create_user("bob", "bob@example.com")
    bob.assign_role(author)

    carol = rbac.create_user("carol", "carol@example.com")
    carol.assign_role(viewer)

    dave = rbac.create_user("dave", "dave@example.com")
    dave.assign_role(moderator)

    return rbac


if __name__ == "__main__":
    rbac = build_demo()
    users = list(rbac.users.values())

    print("=== RBAC Demo ===\n")
    checks = [
        ("posts:read",    "post/42"),
        ("posts:write",   "post/42"),
        ("posts:delete",  "post/42"),
        ("users:manage",  "user/7"),
        ("settings:edit", "site/config"),
        ("comments:mod",  "comment/3"),
    ]
    for user in users:
        print(f"\n{user}")
        for perm_name, resource in checks:
            result = rbac.check_access(user, perm_name, resource)
            icon = "✓" if result else "✗"
            print(f"  {icon}  {perm_name:<20} → {resource}")

    print(f"\n\nAudit log ({len(rbac.audit_log)} entries):")
    for entry in rbac.audit_log[:6]:
        icon = "✓" if entry.granted else "✗"
        print(f"  {icon} [{entry.timestamp}] {entry.user} → {entry.permission}")