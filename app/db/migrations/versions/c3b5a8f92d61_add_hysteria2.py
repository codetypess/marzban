"""Allow Hysteria 2 credentials in the existing proxy table."""

from alembic import op
import sqlalchemy as sa

revision = "c3b5a8f92d61"
down_revision = "4954587cd850"
branch_labels = None
depends_on = None

old_types = ("VMess", "VLESS", "Trojan", "Shadowsocks")


def upgrade():
    # SQLite stores the enum as VARCHAR; MySQL needs its native ENUM extended.
    if op.get_bind().dialect.name == "mysql":
        op.alter_column("proxies", "type", existing_type=sa.Enum(*old_types, name="proxytypes"),
                        type_=sa.Enum(*old_types, "Hysteria2", name="proxytypes"), existing_nullable=False)


def downgrade():
    op.execute(sa.text("DELETE FROM exclude_inbounds_association WHERE proxy_id IN "
                       "(SELECT id FROM proxies WHERE type = 'Hysteria2')"))
    op.execute(sa.text("DELETE FROM proxies WHERE type = 'Hysteria2'"))
    if op.get_bind().dialect.name == "mysql":
        op.alter_column("proxies", "type", existing_type=sa.Enum(*old_types, "Hysteria2", name="proxytypes"),
                        type_=sa.Enum(*old_types, name="proxytypes"), existing_nullable=False)
