"""Isolated database and mocked external services; never starts a proxy core."""

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
test_directory = tempfile.TemporaryDirectory(prefix="marzban-hysteria2-")
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hy2.example.com")])
now = datetime.now(timezone.utc)
cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("hy2.example.com")]), critical=False)
        .sign(key, hashes.SHA256()))
cert_path = Path(test_directory.name, "cert.pem")
key_path = Path(test_directory.name, "key.pem")
cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
native_inbound = {
    "tag": "Hysteria2 HK", "protocol": "hysteria", "port": 443,
    "settings": {"version": 2, "users": []},
    "streamSettings": {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2},
                       "tlsSettings": {"certificates": [{"certificateFile": str(cert_path),
                                                         "keyFile": str(key_path)}]}},
}
os.environ.update(
    SQLALCHEMY_DATABASE_URL=f"sqlite:///{test_directory.name}/test.sqlite3",
    XRAY_JSON=json.dumps({"inbounds": [{"tag": "Trojan TCP", "protocol": "trojan", "port": 8443}, native_inbound],
                          "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}]}),
    TELEGRAM_API_TOKEN="", DEBUG="false", EXTERNAL_CONFIG="",
)
with patch("subprocess.check_output", return_value=b"Xray 26.10.21\n"), \
        patch("requests.get", return_value=Mock(text="1.1.1.1")):
    from app import app, xray

from app.models.admin import Admin as AdminModel  # noqa: E402
from app.db.models import Admin, ClashProxyGroup, ClashSetting, System, JWT  # noqa: E402
from app.db.base import Base, engine  # noqa: E402
from app.db import SessionLocal  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def migrations():
    from alembic import command
    from alembic.config import Config
    command.upgrade(Config("alembic.ini"), "head")


@pytest.fixture
def db(monkeypatch, migrations):
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
    xray.hosts.clear()
    for method in ("_add_user_to_inbound", "_alter_inbound_user", "_remove_user_from_inbound"):
        monkeypatch.setattr(xray.operations, method, Mock())
    app.dependency_overrides[AdminModel.get_current] = lambda: AdminModel(username="admin", is_sudo=True)
    with SessionLocal() as session:
        session.add(Admin(username="admin", hashed_password="test", is_sudo=True))
        session.add(System(id=1))
        session.add(JWT(id=1, secret_key="test-subscription-secret"))
        for name in ("clash", "clash-meta"):
            session.add(ClashSetting(name=name, content="{}"))
        for index, name in enumerate(("DIRECT", "PROXY", "MATCH", "REJECT", "SPEEDTEST"), 1):
            session.add(ClashProxyGroup(id=index, name=name, tag="built-in", type="select",
                                        builtin=True, proxies="...", settings={}))
        session.commit()
        yield session
    app.dependency_overrides.clear()


@pytest.fixture
def client(db):
    from fastapi.testclient import TestClient
    # No context manager: skip startup handlers that launch Xray and Telegram.
    return TestClient(app)
