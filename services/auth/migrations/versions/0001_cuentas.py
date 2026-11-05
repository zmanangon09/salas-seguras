"""Cuentas, catálogo de permisos, roles N:M y sesiones (spec §23.3, Anexo A)."""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

UPGRADE = [
    "REVOKE ALL ON SCHEMA public FROM PUBLIC",
    "GRANT USAGE ON SCHEMA public TO auth_app",
    """CREATE TABLE users (
        id            uuid PRIMARY KEY,
        username      text UNIQUE NOT NULL CHECK (username ~ '^[a-z0-9_.-]{3,32}$'),
        email         text UNIQUE NOT NULL CHECK (length(email) <= 254 AND email ~ '^[^@[:space:]]+@[^@[:space:]]+$'),
        password_hash text NOT NULL,
        status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
        created_at    timestamptz NOT NULL DEFAULT now(),
        updated_at    timestamptz NOT NULL DEFAULT now(),
        created_by    uuid REFERENCES users(id),
        updated_by    uuid REFERENCES users(id)
    )""",
    """CREATE TABLE permissions (
        code        text PRIMARY KEY,
        description text NOT NULL
    )""",
    """CREATE TABLE roles (
        id          uuid PRIMARY KEY,
        name        text UNIQUE NOT NULL CHECK (name ~ '^[A-Z][A-Z0-9_]{2,31}$'),
        description text NOT NULL DEFAULT '',
        status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
        builtin     boolean NOT NULL DEFAULT false,
        created_at  timestamptz NOT NULL DEFAULT now(),
        updated_at  timestamptz NOT NULL DEFAULT now(),
        created_by  uuid REFERENCES users(id),
        updated_by  uuid REFERENCES users(id)
    )""",
    """CREATE TABLE role_permissions (
        role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        permission text NOT NULL REFERENCES permissions(code),
        PRIMARY KEY (role_id, permission)
    )""",
    """CREATE TABLE user_roles (
        id          uuid PRIMARY KEY,
        user_id     uuid NOT NULL REFERENCES users(id),
        role_id     uuid NOT NULL REFERENCES roles(id),
        assigned_at timestamptz NOT NULL DEFAULT now(),
        assigned_by uuid REFERENCES users(id),
        UNIQUE (user_id, role_id)
    )""",
    """CREATE TABLE user_sessions (
        id         uuid PRIMARY KEY,
        user_id    uuid NOT NULL REFERENCES users(id),
        expires_at timestamptz NOT NULL,
        ended_at   timestamptz,
        end_reason text
    )""",
    """CREATE TABLE failed_attempts (
        id         bigserial PRIMARY KEY,
        key        text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX ON failed_attempts (key, created_at)",
    # auth_app hace DML sobre estas tablas, salvo permissions (solo lectura).
    # No puede DELETE en users ni en roles: se desactivan con status.
    # Sí puede DELETE en user_roles y role_permissions.
    "GRANT SELECT, INSERT, UPDATE ON users, roles, user_sessions TO auth_app",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON role_permissions, user_roles TO auth_app",
    "GRANT SELECT ON permissions TO auth_app",
    "GRANT SELECT, INSERT ON failed_attempts TO auth_app",
    "GRANT USAGE ON SEQUENCE failed_attempts_id_seq TO auth_app",
    """INSERT INTO permissions (code, description) VALUES
        ('users.manage', 'Listar, crear y desactivar cuentas'),
        ('roles.manage', 'Crear y editar roles; asignar y retirar roles a usuarios'),
        ('steganography.analyze', 'Enviar imágenes a análisis esteganográfico'),
        ('steganography.results.read', 'Consultar los resultados de los análisis propios'),
        ('steganography.results.read_any', 'Consultar los resultados de cualquier análisis')""",
    """INSERT INTO roles (id, name, description, builtin) VALUES
        ('00000000-0000-4000-8000-000000000001', 'ADMIN', 'Admin global de la plataforma', true),
        ('00000000-0000-4000-8000-000000000002', 'ANALYST', 'Analista de esteganografía', true),
        ('00000000-0000-4000-8000-000000000003', 'USER', 'Usuario estándar de la plataforma', true)""",
    """INSERT INTO role_permissions (role_id, permission) VALUES
        ('00000000-0000-4000-8000-000000000001', 'users.manage'),
        ('00000000-0000-4000-8000-000000000001', 'roles.manage'),
        ('00000000-0000-4000-8000-000000000001', 'steganography.analyze'),
        ('00000000-0000-4000-8000-000000000001', 'steganography.results.read'),
        ('00000000-0000-4000-8000-000000000001', 'steganography.results.read_any'),
        ('00000000-0000-4000-8000-000000000002', 'steganography.analyze'),
        ('00000000-0000-4000-8000-000000000002', 'steganography.results.read')""",
]

DOWNGRADE = [
    "DROP TABLE failed_attempts",
    "DROP TABLE user_sessions",
    "DROP TABLE user_roles",
    "DROP TABLE role_permissions",
    "DROP TABLE roles",
    "DROP TABLE permissions",
    "DROP TABLE users",
]


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
