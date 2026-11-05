"""Registro de cada análisis (spec §23.7, enunciado §2.3)."""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

UPGRADE = [
    "REVOKE ALL ON SCHEMA public FROM PUBLIC",
    "GRANT USAGE ON SCHEMA public TO stego_app",
    """CREATE TABLE analyses (
        id         uuid PRIMARY KEY,
        user_id    uuid NOT NULL,
        filename   text NOT NULL CHECK (length(filename) <= 255),
        mime       text,
        size_bytes integer NOT NULL,
        sha256     char(64) NOT NULL,
        technique  text NOT NULL,
        status     text NOT NULL CHECK (status IN ('sin_indicios', 'sospechoso', 'no_concluyente', 'error')),
        action     text NOT NULL CHECK (action IN ('ninguna', 'cuarentena', 'advertencia', 'rechazo')),
        indicators jsonb NOT NULL,
        reasons    jsonb NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX ON analyses (user_id, created_at)",
    # Los registros no se editan ni se borran (R11).
    "GRANT SELECT, INSERT ON analyses TO stego_app",
]


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TABLE analyses")
