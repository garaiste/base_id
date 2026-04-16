"""Initial schema

Revision ID: 0001
Revises:
Create Date: 2025-01-01 00:00:00
"""
from typing import Sequence, Union
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE userstatus AS ENUM ('pending', 'approved', 'suspended', 'admin');
        EXCEPTION WHEN duplicate_object THEN null;
        END $$;
    """)
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE approvalstatus AS ENUM ('pending', 'approved', 'rejected');
        EXCEPTION WHEN duplicate_object THEN null;
        END $$;
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR UNIQUE NOT NULL,
            password_hash VARCHAR,
            display_name VARCHAR,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            status userstatus NOT NULL DEFAULT 'pending',
            email_verified BOOLEAN NOT NULL DEFAULT false
        )
    """)
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS app_approvals (
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            app_id VARCHAR NOT NULL,
            status approvalstatus NOT NULL DEFAULT 'pending',
            requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            decided_at TIMESTAMPTZ,
            PRIMARY KEY (user_id, app_id)
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id VARCHAR PRIMARY KEY,
            name VARCHAR NOT NULL,
            client_secret_hash VARCHAR NOT NULL,
            redirect_uris JSONB NOT NULL DEFAULT '[]',
            scopes JSONB NOT NULL DEFAULT '[]'
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS auth_codes (
            code VARCHAR PRIMARY KEY,
            client_id VARCHAR NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            redirect_uri VARCHAR NOT NULL,
            scopes JSONB NOT NULL DEFAULT '[]',
            code_challenge VARCHAR,
            code_challenge_method VARCHAR,
            expires_at TIMESTAMPTZ NOT NULL,
            used BOOLEAN NOT NULL DEFAULT false
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash VARCHAR PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            client_id VARCHAR NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
            scopes JSONB NOT NULL DEFAULT '[]',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT false
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS refresh_tokens")
    op.execute("DROP TABLE IF EXISTS auth_codes")
    op.execute("DROP TABLE IF EXISTS oauth_clients")
    op.execute("DROP TABLE IF EXISTS app_approvals")
    op.execute("DROP TABLE IF EXISTS users")
    op.execute("DROP TYPE IF EXISTS approvalstatus")
    op.execute("DROP TYPE IF EXISTS userstatus")