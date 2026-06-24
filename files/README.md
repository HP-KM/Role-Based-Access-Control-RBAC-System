# RBAC System — Database Security Project

## Role-Based Access Control (RBAC)

A full-stack database security implementation covering schema design, access control middleware, and an interactive admin dashboard.

---

## Project Files

| File | Description |
|------|-------------|
| `index.html` | Interactive admin dashboard UI |
| `rbac_schema.sql` | PostgreSQL schema — roles, permissions, audit log |
| `rbac_middleware.py` | Python RBAC engine with decorator-based access control |

---

## Architecture

```
User Request
     │
     ▼
┌─────────────┐
│  Session    │  Validates token, checks expiry
│  Manager    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   RBAC      │  check_permission(user, permission, resource)
│   Engine    │  → Looks up user → roles → permissions
└──────┬──────┘
       │
       ├── DENIED ──► Audit Log → 403 Response
       │
       └── GRANTED
              │
              ▼
       ┌─────────────┐
       │  RLS Filter │  Row-level conditions (e.g. amount < 10000)
       └──────┬──────┘
              │
              ▼
          Database
```

---

## Role Hierarchy

```
Super Admin  (priority 100)  — all permissions
     ⊇
DB Admin     (priority  80)  — no GRANT/REVOKE or user management
     ⊇
Developer    (priority  50)  — write only to dev/staging environments
     ⊇
Analyst      (priority  30)  — SELECT + limited export on analytics_db
     ⊇
Read Only    (priority  10)  — SELECT only, no export
```

---

## Key Security Features

### 1. Principle of Least Privilege
Every role grants only the minimum permissions needed.

### 2. Resource Scoping
Permissions can be scoped globally or to a specific database/table.

### 3. Row-Level Security (RLS)
Fine-grained filters on individual rows:
- Analysts see only payments under $10,000
- Developers see only `env = 'dev'` rows

### 4. MFA Gate
Critical resources (`secrets_vault`, `payments_db`) require MFA verification regardless of role.

### 5. Immutable Audit Log
The audit log uses PostgreSQL `RULE` to block `UPDATE`/`DELETE`, creating a tamper-proof trail.

### 6. Account Locking
After configurable failed login attempts, accounts are time-locked.

### 7. Session TTL
Sessions auto-expire after 30 minutes of inactivity.

---

## Quick Start

### Database Setup
```sql
-- Run as superuser
\i rbac_schema.sql

-- Verify
SELECT * FROM rbac.v_user_permissions LIMIT 10;
```

### Python Usage
```python
from rbac_middleware import rbac, require_permission

# Create a user
user = rbac.create_user("john", "john@co.com", "pass", role_name="analyst")

# Imperative check
if rbac.check_permission(user.user_id, "table:select", "analytics_db"):
    run_query()

# Decorator
@require_permission("table:insert", resource="orders_db")
def create_order(user_id: str, data: dict):
    # Only runs if user has table:insert on orders_db
    ...

# Enforce + audit in one call
rbac.enforce(user.user_id, "schema:drop", resource="users_db")
```

### Run Demo
```bash
python rbac_middleware.py
```

---

## Permissions Reference

| Permission | Category | Description |
|-----------|----------|-------------|
| `table:select` | DML | SELECT queries |
| `table:insert` | DML | INSERT rows |
| `table:update` | DML | UPDATE rows |
| `table:delete` | DML | DELETE rows |
| `schema:create` | DDL | CREATE tables/indexes |
| `schema:drop` | DDL | DROP tables/databases |
| `schema:alter` | DDL | ALTER table structure |
| `schema:truncate` | DDL | TRUNCATE tables |
| `data:export` | DATA | Export to files |
| `data:backup` | DATA | Backup/restore |
| `access:grant` | DCL | GRANT to others |
| `access:revoke` | DCL | REVOKE from others |
| `admin:users` | ADMIN | Manage user accounts |
| `admin:roles` | ADMIN | Manage roles |
| `admin:audit` | ADMIN | View audit logs |
| `admin:settings` | ADMIN | Change security settings |

---

## Compliance Coverage

- **SOC 2**: Audit logging, access controls, session management
- **GDPR**: Data minimization via RLS, PII masking for non-admin roles
- **PCI-DSS**: MFA for payment data, encryption at rest setting, immutable logs
- **ISO 27001**: Role hierarchy, least privilege, regular access review via `v_inactive_users`
