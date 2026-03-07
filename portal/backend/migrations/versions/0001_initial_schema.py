"""initial schema

Revision ID: 0001
Revises: 
Create Date: 2025-01-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # users first (referenced by other tables)
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(320), nullable=False),
        sa.Column('password_hash', sa.String(128), nullable=True),
        sa.Column('display_name', sa.String(256), nullable=True),
        sa.Column('org_id', sa.String(256), nullable=True),
        sa.Column('role', sa.Enum('enterprise', 'admin', name='user_role_enum'), nullable=False),
        sa.Column('totp_secret_encrypted', sa.Text, nullable=True),
        sa.Column('mfa_enabled', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('sso_provider', sa.String(64), nullable=True),
        sa.Column('sso_subject', sa.String(256), nullable=True),
        sa.Column('active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('sso_provider', 'sso_subject', name='uq_users_sso'),
    )
    op.create_index('ix_users_email', 'users', ['email'])

    op.create_table(
        'public_keys',
        sa.Column('fingerprint', sa.String(64), nullable=False),
        sa.Column('pem', sa.Text, nullable=False),
        sa.Column('issuer_org', sa.String(256), nullable=False),
        sa.Column('algorithm', sa.String(32), nullable=False),
        sa.Column('active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('rotated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('notes', sa.Text, nullable=True),
        sa.PrimaryKeyConstraint('fingerprint'),
    )

    op.create_table(
        'certificates',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('schema_version', sa.String(16), nullable=False, server_default='1.0'),
        sa.Column('issuer_org', sa.String(256), nullable=False),
        sa.Column('portal_verification_url', sa.Text, nullable=False),
        sa.Column('public_key_fingerprint', sa.String(64), nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('registered_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('wipe_standard', sa.String(128), nullable=False),
        sa.Column('passes_completed', sa.Integer, nullable=False),
        sa.Column('verified', sa.Boolean, nullable=False),
        sa.Column('duration_seconds', sa.Float, nullable=True),
        sa.Column('sha256_before', sa.String(64), nullable=True),
        sa.Column('sha3_256_before', sa.String(64), nullable=True),
        sa.Column('sha256_after', sa.String(64), nullable=True),
        sa.Column('sha3_256_after', sa.String(64), nullable=True),
        sa.Column('compliance_frameworks', postgresql.JSONB, nullable=False,
                  server_default='[]'),
        sa.Column('signature_algorithm', sa.String(32), nullable=False),
        sa.Column('signature_value', sa.Text, nullable=False),
        sa.Column('operator_encrypted', sa.Text, nullable=True),
        sa.Column('target_encrypted', sa.Text, nullable=True),
        sa.Column('pass_detail_encrypted', sa.Text, nullable=True),
        sa.Column('compliance_detail_encrypted', sa.Text, nullable=True),
        sa.Column('previous_certificate_hash', sa.String(64), nullable=True),
        sa.Column('chain_position', sa.Integer, nullable=True),
        sa.Column('revoked', sa.Boolean, nullable=False, server_default='false'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_certificates_wipe_standard', 'certificates', ['wipe_standard'])
    op.create_index('ix_certificates_generated_at', 'certificates', ['generated_at'])
    op.create_index('ix_certificates_revoked', 'certificates', ['revoked'])
    op.create_index('ix_certificates_public_key_fingerprint', 'certificates',
                    ['public_key_fingerprint'])

    op.create_table(
        'verification_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('certificate_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('result', sa.Enum('valid', 'invalid', 'tampered', 'not_found', 'revoked',
                                     name='verification_result_enum'), nullable=False),
        sa.Column('method', sa.Enum('file_upload', 'id_lookup', 'qr_scan',
                                     name='verification_method_enum'), nullable=False),
        sa.Column('tier', sa.Enum('public', 'enterprise', 'admin',
                                   name='access_tier_enum'), nullable=False,
                  server_default='public'),
        sa.Column('ip_hash', sa.String(64), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('flagged', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('flag_reason', sa.Text, nullable=True),
        sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'],
                                 ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_ve_certificate_id', 'verification_events', ['certificate_id'])
    op.create_index('ix_ve_verified_at', 'verification_events', ['verified_at'])
    op.create_index('ix_ve_result', 'verification_events', ['result'])
    op.create_index('ix_ve_flagged', 'verification_events', ['flagged'])

    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('key_hash', sa.String(64), nullable=False),
        sa.Column('key_prefix', sa.String(8), nullable=False),
        sa.Column('label', sa.String(256), nullable=False),
        sa.Column('org_id', sa.String(256), nullable=True),
        sa.Column('tier', sa.Enum('enterprise', 'admin', name='api_key_tier_enum'),
                  nullable=False, server_default='enterprise'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('created_by_user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash'),
    )
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'])
    op.create_index('ix_api_keys_revoked', 'api_keys', ['revoked'])

    op.create_table(
        'revocations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('certificate_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('revoked_by_user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('reason', sa.Text, nullable=False),
        sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'],
                                 ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['revoked_by_user_id'], ['users.id'],
                                 ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('certificate_id'),
    )


def downgrade() -> None:
    op.drop_table('revocations')
    op.drop_table('api_keys')
    op.drop_table('verification_events')
    op.drop_table('certificates')
    op.drop_table('public_keys')
    op.drop_table('users')
    op.execute("DROP TYPE IF EXISTS verification_result_enum")
    op.execute("DROP TYPE IF EXISTS verification_method_enum")
    op.execute("DROP TYPE IF EXISTS access_tier_enum")
    op.execute("DROP TYPE IF EXISTS user_role_enum")
    op.execute("DROP TYPE IF EXISTS api_key_tier_enum")
