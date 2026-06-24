-- ============================================================
--   RBAC SYSTEM — DATABASE SECURITY
--   Role-Based Access Control Schema
--   Compatible with: PostgreSQL 14+
-- ============================================================

-- ── SETUP ──────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS rbac;
SET search_path = rbac, public;

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- 1. ROLES TABLE
-- ============================================================
CREATE TABLE rbac.roles (
    role_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_name    VARCHAR(50)  NOT NULL UNIQUE,
    description  TEXT,
    priority     INT          NOT NULL DEFAULT 0,  -- higher = more privilege
    is_system    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Seed default roles (ordered by privilege level)
INSERT INTO rbac.roles (role_name, description, priority, is_system) VALUES
  ('super_admin',  'Full system access. Can manage all roles, users, and configurations.', 100, TRUE),
  ('db_admin',     'Database management. No user/role provisioning.',                       80,  TRUE),
  ('developer',    'Read/write on dev and staging only. No production write.',              50,  TRUE),
  ('analyst',      'Read-only on analytics and reporting databases.',                       30,  TRUE),
  ('read_only',    'SELECT-only on approved tables. No data export.',                       10,  TRUE);

-- ============================================================
-- 2. RESOURCES TABLE  (databases, schemas, tables, columns)
-- ============================================================
CREATE TABLE rbac.resources (
    resource_id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource_type VARCHAR(20) NOT NULL CHECK (resource_type IN ('database','schema','table','column','procedure')),
    resource_name VARCHAR(200) NOT NULL,
    parent_id     UUID REFERENCES rbac.resources(resource_id) ON DELETE CASCADE,
    sensitivity   VARCHAR(10) NOT NULL DEFAULT 'LOW' CHECK (sensitivity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed resource tree
INSERT INTO rbac.resources (resource_type, resource_name, sensitivity) VALUES
  ('database', 'users_db',      'HIGH'),
  ('database', 'orders_db',     'MEDIUM'),
  ('database', 'analytics_db',  'LOW'),
  ('database', 'payments_db',   'CRITICAL'),
  ('database', 'dev_db',        'LOW'),
  ('database', 'secrets_vault', 'CRITICAL');

-- ============================================================
-- 3. PERMISSIONS TABLE
-- ============================================================
CREATE TABLE rbac.permissions (
    permission_id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    permission_name VARCHAR(50) NOT NULL UNIQUE,  -- e.g. 'db:read', 'table:write'
    category        VARCHAR(30) NOT NULL,          -- 'DML','DDL','DCL','ADMIN'
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO rbac.permissions (permission_name, category, description) VALUES
  -- DML
  ('table:select',   'DML', 'Run SELECT queries on tables'),
  ('table:insert',   'DML', 'Insert new rows into tables'),
  ('table:update',   'DML', 'Update existing rows in tables'),
  ('table:delete',   'DML', 'Delete rows from tables'),
  -- DDL
  ('schema:create',  'DDL', 'Create tables, indexes, views'),
  ('schema:drop',    'DDL', 'Drop tables, schemas, databases'),
  ('schema:alter',   'DDL', 'Alter table structure'),
  ('schema:truncate','DDL', 'Truncate (wipe) tables'),
  -- DATA
  ('data:export',    'DATA','Export table data to files'),
  ('data:backup',    'DATA','Create and restore database backups'),
  ('data:import',    'DATA','Bulk import data from external sources'),
  -- DCL
  ('access:grant',   'DCL', 'Grant permissions to other users'),
  ('access:revoke',  'DCL', 'Revoke permissions from users'),
  -- ADMIN
  ('admin:users',    'ADMIN','Create, edit, delete user accounts'),
  ('admin:roles',    'ADMIN','Create, edit, delete roles'),
  ('admin:audit',    'ADMIN','View full audit logs'),
  ('admin:settings', 'ADMIN','Modify system security settings');

-- ============================================================
-- 4. ROLE–PERMISSION MAPPING
-- ============================================================
CREATE TABLE rbac.role_permissions (
    role_id       UUID NOT NULL REFERENCES rbac.roles(role_id)       ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES rbac.permissions(permission_id) ON DELETE CASCADE,
    resource_id   UUID REFERENCES rbac.resources(resource_id) ON DELETE CASCADE,  -- NULL = all resources
    conditions    JSONB,       -- optional row-level conditions
    granted_by    UUID,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id, COALESCE(resource_id, '00000000-0000-0000-0000-000000000000'::UUID))
);

-- Helper to assign permissions by name
CREATE OR REPLACE FUNCTION rbac.grant_role_permission(
    p_role_name       TEXT,
    p_permission_name TEXT,
    p_resource_name   TEXT   DEFAULT NULL,
    p_conditions      JSONB  DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_role_id       UUID;
    v_permission_id UUID;
    v_resource_id   UUID;
BEGIN
    SELECT role_id       INTO v_role_id       FROM rbac.roles       WHERE role_name       = p_role_name;
    SELECT permission_id INTO v_permission_id FROM rbac.permissions  WHERE permission_name = p_permission_name;
    IF p_resource_name IS NOT NULL THEN
        SELECT resource_id INTO v_resource_id FROM rbac.resources WHERE resource_name = p_resource_name;
    END IF;

    INSERT INTO rbac.role_permissions (role_id, permission_id, resource_id, conditions)
    VALUES (v_role_id, v_permission_id, v_resource_id, p_conditions)
    ON CONFLICT DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- ── Assign permissions ──────────────────────────────────────
-- super_admin: everything
SELECT rbac.grant_role_permission('super_admin', p) FROM unnest(ARRAY[
  'table:select','table:insert','table:update','table:delete',
  'schema:create','schema:drop','schema:alter','schema:truncate',
  'data:export','data:backup','data:import',
  'access:grant','access:revoke',
  'admin:users','admin:roles','admin:audit','admin:settings'
]) AS p;

-- db_admin: everything except DCL and admin:users/roles
SELECT rbac.grant_role_permission('db_admin', p) FROM unnest(ARRAY[
  'table:select','table:insert','table:update','table:delete',
  'schema:create','schema:alter','schema:truncate',
  'data:export','data:backup','admin:audit'
]) AS p;

-- developer: DML only on dev_db; select everywhere
SELECT rbac.grant_role_permission('developer', 'table:select');
SELECT rbac.grant_role_permission('developer', 'table:insert',   'dev_db');
SELECT rbac.grant_role_permission('developer', 'table:update',   'dev_db');
SELECT rbac.grant_role_permission('developer', 'table:delete',   'dev_db');
SELECT rbac.grant_role_permission('developer', 'schema:create',  'dev_db');
SELECT rbac.grant_role_permission('developer', 'data:export',    'dev_db');

-- analyst: read-only + export on analytics_db
SELECT rbac.grant_role_permission('analyst', 'table:select');
SELECT rbac.grant_role_permission('analyst', 'data:export', 'analytics_db',
    '{"row_filter": "amount < 10000"}'::JSONB);

-- read_only: select only
SELECT rbac.grant_role_permission('read_only', 'table:select');

-- ============================================================
-- 5. USERS TABLE
-- ============================================================
CREATE TABLE rbac.users (
    user_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username       VARCHAR(100) NOT NULL UNIQUE,
    email          VARCHAR(200) NOT NULL UNIQUE,
    password_hash  TEXT         NOT NULL,
    is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
    mfa_enabled    BOOLEAN      NOT NULL DEFAULT FALSE,
    last_login     TIMESTAMPTZ,
    failed_attempts INT          NOT NULL DEFAULT 0,
    locked_until   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 6. USER–ROLE ASSIGNMENTS
-- ============================================================
CREATE TABLE rbac.user_roles (
    user_id    UUID NOT NULL REFERENCES rbac.users(user_id)  ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES rbac.roles(role_id)  ON DELETE CASCADE,
    granted_by UUID REFERENCES rbac.users(user_id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,    -- optional TTL for temporary access
    PRIMARY KEY (user_id, role_id)
);

-- ============================================================
-- 7. AUDIT LOG (immutable — no UPDATE/DELETE allowed)
-- ============================================================
CREATE TABLE rbac.audit_log (
    log_id        BIGSERIAL    PRIMARY KEY,
    event_time    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    user_id       UUID         REFERENCES rbac.users(user_id),
    username      VARCHAR(100),
    role_name     VARCHAR(50),
    action        VARCHAR(50)  NOT NULL,   -- GRANTED, DENIED, LOGIN, LOGOUT, ESCALATION …
    resource_type VARCHAR(30),
    resource_name VARCHAR(200),
    query_preview TEXT,
    ip_address    INET,
    session_id    UUID,
    result        VARCHAR(20)  NOT NULL CHECK (result IN ('SUCCESS','DENIED','ERROR','MFA_REQUIRED')),
    metadata      JSONB
);

-- Make audit log append-only
CREATE RULE no_audit_update AS ON UPDATE TO rbac.audit_log DO INSTEAD NOTHING;
CREATE RULE no_audit_delete AS ON DELETE TO rbac.audit_log DO INSTEAD NOTHING;

-- ============================================================
-- 8. SESSIONS TABLE
-- ============================================================
CREATE TABLE rbac.sessions (
    session_id    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID        NOT NULL REFERENCES rbac.users(user_id) ON DELETE CASCADE,
    ip_address    INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 minutes',
    is_valid      BOOLEAN     NOT NULL DEFAULT TRUE
);

-- ============================================================
-- 9. ACCESS CONTROL FUNCTION
-- ============================================================
CREATE OR REPLACE FUNCTION rbac.check_permission(
    p_user_id       UUID,
    p_permission    TEXT,
    p_resource_name TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_has_perm  BOOLEAN := FALSE;
    v_is_active BOOLEAN;
    v_locked    TIMESTAMPTZ;
BEGIN
    -- Check user is active and not locked
    SELECT is_active, locked_until INTO v_is_active, v_locked
    FROM rbac.users WHERE user_id = p_user_id;

    IF NOT v_is_active OR (v_locked IS NOT NULL AND v_locked > NOW()) THEN
        RETURN FALSE;
    END IF;

    -- Check via role hierarchy
    SELECT EXISTS (
        SELECT 1
        FROM rbac.user_roles ur
        JOIN rbac.role_permissions rp ON ur.role_id = rp.role_id
        JOIN rbac.permissions p        ON rp.permission_id = p.permission_id
        LEFT JOIN rbac.resources res   ON rp.resource_id = res.resource_id
        WHERE ur.user_id = p_user_id
          AND p.permission_name = p_permission
          AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
          AND (
              rp.resource_id IS NULL           -- global permission
              OR res.resource_name = p_resource_name
          )
    ) INTO v_has_perm;

    RETURN v_has_perm;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================
-- 10. ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================

-- Enable RLS on a sensitive table (example: payments)
-- In your real schema, run this on the actual table:
--
-- ALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;
--
-- CREATE POLICY analyst_payment_limit ON public.payments
--   FOR SELECT
--   TO analyst_role
--   USING (amount < 10000);
--
-- CREATE POLICY developer_env_filter ON public.users
--   FOR ALL
--   TO developer_role
--   USING (env = current_setting('app.environment'));

-- ============================================================
-- 11. HELPER VIEWS
-- ============================================================
CREATE OR REPLACE VIEW rbac.v_user_permissions AS
SELECT
    u.username,
    u.email,
    r.role_name,
    p.permission_name,
    p.category,
    res.resource_name,
    res.sensitivity,
    rp.conditions
FROM rbac.users u
JOIN rbac.user_roles       ur  ON u.user_id       = ur.user_id
JOIN rbac.roles             r  ON ur.role_id       = r.role_id
JOIN rbac.role_permissions rp  ON r.role_id        = rp.role_id
JOIN rbac.permissions       p  ON rp.permission_id = p.permission_id
LEFT JOIN rbac.resources   res ON rp.resource_id   = res.resource_id
WHERE u.is_active = TRUE
  AND (ur.expires_at IS NULL OR ur.expires_at > NOW());

CREATE OR REPLACE VIEW rbac.v_inactive_users AS
SELECT username, email, last_login,
       NOW() - last_login AS inactive_for
FROM rbac.users
WHERE is_active = TRUE
  AND last_login < NOW() - INTERVAL '30 days';

-- ============================================================
-- 12. INDEXES
-- ============================================================
CREATE INDEX idx_user_roles_user    ON rbac.user_roles    (user_id);
CREATE INDEX idx_user_roles_role    ON rbac.user_roles    (role_id);
CREATE INDEX idx_role_perms_role    ON rbac.role_permissions(role_id);
CREATE INDEX idx_audit_user         ON rbac.audit_log     (user_id);
CREATE INDEX idx_audit_time         ON rbac.audit_log     (event_time DESC);
CREATE INDEX idx_audit_result       ON rbac.audit_log     (result) WHERE result = 'DENIED';
CREATE INDEX idx_sessions_user      ON rbac.sessions      (user_id, is_valid);

-- ============================================================
-- DONE
-- ============================================================
-- To verify setup:
--   SELECT * FROM rbac.v_user_permissions LIMIT 20;
--   SELECT rbac.check_permission('<user_uuid>', 'table:select', 'analytics_db');
