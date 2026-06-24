"""
RBAC REST API  —  FastAPI sample
=================================
Endpoints that demonstrate CRUD on users/roles/permissions
and a /check endpoint for runtime access control.

Run with:  uvicorn api:app --reload
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from rbac import RBACManager, build_demo

app = FastAPI(title="RBAC API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared state (in-memory for demo)
rbac = build_demo()


# ── Pydantic schemas ──────────────────────────────────────────────────────

class PermissionOut(BaseModel):
    name: str
    description: str

class RoleOut(BaseModel):
    name: str
    description: str
    permissions: list[str]

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    roles: list[str]
    active: bool
    permissions: list[str]

class AssignRoleBody(BaseModel):
    role_name: str

class CheckBody(BaseModel):
    user_id: int
    permission: str
    resource: Optional[str] = ""

class CheckResult(BaseModel):
    user: str
    permission: str
    resource: str
    granted: bool
    reason: str

class AuditEntry(BaseModel):
    timestamp: str
    user: str
    permission: str
    resource: str
    granted: bool
    reason: str

class CreateUserBody(BaseModel):
    username: str
    email: str

class CreateRoleBody(BaseModel):
    name: str
    description: str

class CreatePermissionBody(BaseModel):
    name: str
    description: str

class RolePermissionBody(BaseModel):
    permission_name: str


# ── Helpers ───────────────────────────────────────────────────────────────

def user_out(u) -> UserOut:
    return UserOut(
        id=u.id,
        username=u.username,
        email=u.email,
        roles=[r.name for r in u.roles],
        active=u.active,
        permissions=sorted(p.name for p in u.all_permissions()),
    )

def role_out(r) -> RoleOut:
    return RoleOut(
        name=r.name,
        description=r.description,
        permissions=sorted(p.name for p in r.permissions),
    )


# ── Permissions ───────────────────────────────────────────────────────────

@app.get("/permissions", response_model=list[PermissionOut], tags=["Permissions"])
def list_permissions():
    """List all registered permissions."""
    return [PermissionOut(name=p.name, description=p.description)
            for p in rbac.permissions.values()]

@app.post("/permissions", response_model=PermissionOut, status_code=201, tags=["Permissions"])
def create_permission(body: CreatePermissionBody):
    """Register a new permission."""
    if body.name in rbac.permissions:
        raise HTTPException(400, f"Permission '{body.name}' already exists")
    perm = rbac.create_permission(body.name, body.description)
    return PermissionOut(name=perm.name, description=perm.description)


# ── Roles ─────────────────────────────────────────────────────────────────

@app.get("/roles", response_model=list[RoleOut], tags=["Roles"])
def list_roles():
    """List all roles with their permissions."""
    return [role_out(r) for r in rbac.roles.values()]

@app.post("/roles", response_model=RoleOut, status_code=201, tags=["Roles"])
def create_role(body: CreateRoleBody):
    """Create a new role."""
    if body.name in rbac.roles:
        raise HTTPException(400, f"Role '{body.name}' already exists")
    role = rbac.create_role(body.name, body.description)
    return role_out(role)

@app.post("/roles/{role_name}/permissions", response_model=RoleOut, tags=["Roles"])
def add_permission_to_role(role_name: str, body: RolePermissionBody):
    """Grant a permission to a role."""
    role = rbac.get_role(role_name)
    if not role:
        raise HTTPException(404, f"Role '{role_name}' not found")
    perm = rbac.get_permission(body.permission_name)
    if not perm:
        raise HTTPException(404, f"Permission '{body.permission_name}' not found")
    role.add_permission(perm)
    return role_out(role)

@app.delete("/roles/{role_name}/permissions/{perm_name}", response_model=RoleOut, tags=["Roles"])
def remove_permission_from_role(role_name: str, perm_name: str):
    """Revoke a permission from a role."""
    role = rbac.get_role(role_name)
    if not role:
        raise HTTPException(404, f"Role '{role_name}' not found")
    perm = rbac.get_permission(perm_name)
    if not perm:
        raise HTTPException(404, f"Permission '{perm_name}' not found")
    role.remove_permission(perm)
    return role_out(role)


# ── Users ─────────────────────────────────────────────────────────────────

@app.get("/users", response_model=list[UserOut], tags=["Users"])
def list_users():
    """List all users with their effective permissions."""
    return [user_out(u) for u in rbac.users.values()]

@app.post("/users", response_model=UserOut, status_code=201, tags=["Users"])
def create_user(body: CreateUserBody):
    """Create a new user (no roles assigned yet)."""
    user = rbac.create_user(body.username, body.email)
    return user_out(user)

@app.get("/users/{user_id}", response_model=UserOut, tags=["Users"])
def get_user(user_id: int):
    user = rbac.get_user(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return user_out(user)

@app.post("/users/{user_id}/roles", response_model=UserOut, tags=["Users"])
def assign_role(user_id: int, body: AssignRoleBody):
    """Assign a role to a user."""
    user = rbac.get_user(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    role = rbac.get_role(body.role_name)
    if not role:
        raise HTTPException(404, f"Role '{body.role_name}' not found")
    user.assign_role(role)
    return user_out(user)

@app.delete("/users/{user_id}/roles/{role_name}", response_model=UserOut, tags=["Users"])
def revoke_role(user_id: int, role_name: str):
    """Revoke a role from a user."""
    user = rbac.get_user(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    role = rbac.get_role(role_name)
    if not role:
        raise HTTPException(404, f"Role '{role_name}' not found")
    user.revoke_role(role)
    return user_out(user)

@app.patch("/users/{user_id}/deactivate", response_model=UserOut, tags=["Users"])
def deactivate_user(user_id: int):
    """Deactivate a user (blocks all access)."""
    user = rbac.get_user(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.active = False
    return user_out(user)


# ── Access Check ──────────────────────────────────────────────────────────

@app.post("/check", response_model=CheckResult, tags=["Access Control"])
def check_access(body: CheckBody):
    """
    Core RBAC gate: does user X have permission Y on resource Z?
    Returns granted=true/false and logs the decision.
    """
    user = rbac.get_user(body.user_id)
    if not user:
        raise HTTPException(404, "User not found")
    perm = rbac.get_permission(body.permission)
    if not perm:
        raise HTTPException(404, f"Permission '{body.permission}' not found")

    granted = rbac.check_access(user, body.permission, body.resource)
    last = rbac.audit_log[-1]
    return CheckResult(
        user=user.username,
        permission=body.permission,
        resource=body.resource,
        granted=granted,
        reason=last.reason,
    )


# ── Audit Log ─────────────────────────────────────────────────────────────

@app.get("/audit", response_model=list[AuditEntry], tags=["Audit"])
def get_audit_log(limit: int = Query(50, le=200)):
    """Return the last N access decisions."""
    entries = rbac.audit_log[-limit:]
    return [AuditEntry(**e.__dict__) for e in reversed(entries)]
