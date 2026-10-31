import base64
import json
import ipaddress
import os
from datetime import datetime, timedelta
from urllib.parse import parse_qs, unquote, urlsplit
from unittest.mock import Mock, patch

import pytest
import yaml
from pydantic import ValidationError

from app import xray
from app.xray import operations
from app.db import crud
from app.db.models import Admin, NodeUserUsage
from app.models.clash import ClashProxyCreate
from app.models.proxy import Hysteria2Settings
from app.models.user import UserCreate, UserResponse
from app.routers.clash import ClashConfig, generate_subscription_with_rules, generate_v2ray_links
from app.subscription.share import generate_subscription


def make_user(db, username="alice", tags="", **kwargs):
    user = crud.create_user(db, UserCreate(username=username, proxies={"hysteria2": {}},
                            inbounds={"hysteria2": ["Hysteria2 HK"]}, sub_tags=tags, **kwargs),
                            admin=db.query(Admin).first())
    user.sub_tags = tags
    user.sub_url_prefix = "https://sub.example.com" if tags else ""
    db.commit()
    return user


def make_node(db, **kwargs):
    return crud.create_clash_proxy(db, ClashProxyCreate(**{
        "name": "HK", "server": "hy2.example.com", "port": "443", "tag": "hk",
        "inbound": "Hysteria2 HK", "settings": {}, **kwargs,
    }))


def test_personal_credentials_and_node_groups(db):
    alice = make_user(db, tags="hk")
    bob = make_user(db, username="bob", tags="hk")
    make_node(db, settings={"hysteria2": {"obfs": "salamander", "obfs_password": "shared"}})
    option = ClashConfig.Option()
    option.support_hysteria2 = True
    result = []
    for user in (alice, bob):
        content = generate_subscription_with_rules(db, user, "mihomo", option)
        config = yaml.safe_load(content)
        assert config["proxies"][0]["password"] == user.proxies[0].settings["password"]
        assert config["proxies"][0]["obfs-password"] == "shared"
        assert "HK" in config["proxy-groups"][0]["proxies"]
        result.append(config["proxies"][0]["password"])
    assert result[0] != result[1]


def test_unsupported_client_and_tags_are_filtered(db):
    user = make_user(db, tags="hk")
    make_node(db)
    make_node(db, name="Other", tag="other")
    option = ClashConfig.Option()
    config = yaml.safe_load(generate_subscription_with_rules(db, user, "clash", option))
    assert config.get("proxies", []) == []
    assert all("HK" not in group["proxies"] for group in config["proxy-groups"])
    option.support_hysteria2 = True
    config = yaml.safe_load(generate_subscription_with_rules(db, user, "mihomo", option))
    assert [p["name"] for p in config["proxies"]] == ["HK"]


def test_share_link_encodes_ipv6_and_password(db):
    user = make_user(db, tags="hk")
    user.proxies[0].settings = {"password": "密码:@/#?"}
    db.commit()
    make_node(db, server="2001:db8::1", name="香港")
    link, = generate_v2ray_links(user.username, db)
    parsed = urlsplit(link)
    assert parsed.scheme == "hysteria2"
    assert parsed.hostname == "2001:db8::1"
    assert parsed.port == 443
    assert unquote(parsed.username) == "密码:@/#?"
    assert unquote(parsed.fragment) == "香港"
    assert parse_qs(parsed.query)["sni"] == ["hy2.example.com"]


@pytest.mark.parametrize("format", ["v2ray", "clash-meta", "sing-box", "clash", "outline", "v2ray-json"])
def test_default_subscription_formats(db, format):
    user = UserResponse.model_validate(make_user(db))
    result = generate_subscription(user, format, as_base64=False, reverse=False)
    if format in ("v2ray", "clash-meta", "sing-box", "v2ray-json"):
        assert "hysteria" in result
        assert user.proxies["hysteria2"].password in unquote(result)
    else:
        assert "hysteria2" not in result


def test_registration_and_existing_user_api(client, db):
    response = client.get("/api/inbounds")
    assert response.status_code == 200
    assert response.json()["hysteria2"][0]["network"] == "udp"
    response = client.get("/api/clash/proxy/inbounds")
    inbound = next(i for i in response.json()["data"] if i["type"] == "hysteria2")
    assert inbound["settings"]["sni"] == "hy2.example.com"
    assert "certificateFile" not in response.text
    assert "keyFile" not in response.text
    response = client.post("/api/user", json={"username": "alice", "proxies": {"hysteria2": {}},
                                              "sub_tags": "hk", "sub_url_prefix": "https://sub.example.com/"})
    assert response.status_code == 200, response.text
    assert response.json()["proxies"]["hysteria2"]["password"]
    assert response.json()["inbounds"]["hysteria2"] == ["Hysteria2 HK"]
    assert xray.operations._add_user_to_inbound.call_count == 1
    account = xray.operations._add_user_to_inbound.call_args.args[2]
    assert account.password == response.json()["proxies"]["hysteria2"]["password"]


def test_existing_xray_protocol_still_exports(db):
    user = crud.create_user(db, UserCreate(username="alice", proxies={"trojan": {}}))
    response = UserResponse.model_validate(user)
    assert response.links[0].startswith("trojan://")
    operations.add_user(user)
    assert xray.operations._add_user_to_inbound.call_count == 1


@pytest.mark.parametrize("port", ["0", "65536", "500:400", "443:"])
def test_invalid_hysteria2_ports(db, port):
    with pytest.raises(ValidationError):
        make_node(db, port=port)


def test_obfs_validation_and_random_credential_generation(db):
    with pytest.raises(ValidationError):
        make_node(db, settings={"hysteria2": {"obfs": "salamander"}})
    assert Hysteria2Settings().password != Hysteria2Settings().password
    with pytest.raises(ValidationError):
        UserCreate(username="alice", proxies={"hysteria2": {}}, inbounds={"hysteria2": ["Trojan TCP"]})


def test_mixed_protocols_use_existing_xray_management(db):
    user = crud.create_user(db, UserCreate(username="alice", proxies={"trojan": {}, "hysteria2": {}}))
    operations.add_user(user)
    assert xray.operations._add_user_to_inbound.call_count == 2
    generated = xray.config.include_db_users()
    clients = generated.get_inbound("Trojan TCP")["settings"]["clients"]
    assert len(clients) == 1
    assert clients[0]["password"] == next(p.settings["password"] for p in user.proxies if p.type == "trojan")
    native = generated.get_inbound("Hysteria2 HK")
    assert native["protocol"] == "hysteria"
    account, = native["settings"]["users"]
    assert account == {"email": f"{user.id}.alice", "auth": next(p.settings["password"] for p in user.proxies if p.type == "hysteria2")}
    assert "clients" not in native["settings"]


def test_node_crud_range_and_hidden_setting(client, db):
    user = make_user(db, tags="hk")
    payload = {"name": "HK", "server": "hy2.example.com", "port": "443:444", "tag": "hk",
               "inbound": "Hysteria2 HK", "settings": {"hidden": True, "hysteria2": {"sni": "cert.example.com"}}}
    response = client.post("/api/clash/proxy", json=payload)
    assert response.status_code == 200, response.text
    option = ClashConfig.Option()
    option.support_hysteria2 = True
    config = yaml.safe_load(generate_subscription_with_rules(db, user, "mihomo", option))
    assert [p["port"] for p in config["proxies"]] == [443, 444]
    assert all(p["sni"] == "cert.example.com" for p in config["proxies"])
    assert all("HK" not in g["proxies"] for g in config["proxy-groups"][:5])
    proxy_id = response.json()["id"]
    payload["port"] = "443"
    payload["settings"]["hidden"] = False
    assert client.put(f"/api/clash/proxy/{proxy_id}", json=payload).status_code == 200
    assert client.delete(f"/api/clash/proxy/{proxy_id}").status_code == 200


def test_native_account_uses_xray_protobuf(db):
    from xray_api.proto.proxy.hysteria.account.config_pb2 import Account
    user = make_user(db)
    operations.add_user(user)
    call, = xray.operations._add_user_to_inbound.call_args_list
    api, tag, account = call.args
    assert api is xray.api
    assert tag == "Hysteria2 HK"
    assert account.email == f"{user.id}.alice"
    assert account.message.type == "xray.proxy.hysteria.account.Account"
    assert Account.FromString(account.message.value).auth == user.proxies[0].settings["password"]


@pytest.mark.parametrize("status,expected", [("active", 1), ("on_hold", 1), ("disabled", 0), ("expired", 0), ("limited", 0)])
def test_native_startup_respects_existing_user_statuses(db, status, expected):
    user = make_user(db)
    user.status = status
    db.commit()
    assert len(xray.config.include_db_users().get_inbound("Hysteria2 HK")["settings"]["users"]) == expected


def test_native_revoke_and_inbound_permissions(db):
    user = make_user(db)
    old = user.proxies[0].settings["password"]
    crud.revoke_user_sub(db, user)
    operations.update_user(user)
    account = xray.operations._alter_inbound_user.call_args.args[2]
    assert account.password != old
    assert account.password == user.proxies[0].settings["password"]
    user.proxies[0].excluded_inbounds.append(crud.get_or_create_inbound(db, "Hysteria2 HK"))
    db.commit()
    assert xray.config.include_db_users().get_inbound("Hysteria2 HK")["settings"]["users"] == []
    xray.operations._alter_inbound_user.reset_mock()
    operations.update_user(user)
    xray.operations._alter_inbound_user.assert_not_called()
    assert "Hysteria2 HK" in [call.args[1] for call in xray.operations._remove_user_from_inbound.call_args_list]


def test_native_uses_existing_traffic_job_and_quota_review(db):
    from app.jobs import record_usages, review_users
    user = make_user(db, data_limit=10)
    stats = [Mock(name="unused", value=7), Mock(name="unused", value=3)]
    for stat in stats:
        stat.name = f"{user.id}.alice"
    with patch.object(xray.api, "get_users_stats", return_value=stats):
        record_usages.record_user_usages()
    db.expire_all()
    assert user.used_traffic == 10
    assert user.online_at is not None
    assert db.query(Admin).first().users_usage == 10
    assert db.query(NodeUserUsage).one().used_traffic == 10
    with patch.object(review_users.report, "status_change"):
        review_users.review()
    db.expire_all()
    assert user.status == "limited"
    assert "Hysteria2 HK" in [call.args[1] for call in xray.operations._remove_user_from_inbound.call_args_list]


@pytest.mark.parametrize("field", ["network", "method"])
def test_native_inbound_parses_xray_tls_and_salamander(field):
    from app.xray.config import XRayConfig
    raw = json.loads(os.environ["XRAY_JSON"])
    stream = next(i for i in raw["inbounds"] if i["protocol"] == "hysteria")["streamSettings"]
    stream.pop("network", None)
    stream[field] = "hysteria"
    stream["finalmask"] = {"udp": [{"type": "salamander", "settings": {"password": "shared"}}]}
    native = XRayConfig(raw)
    assert native.inbounds_by_tag["Hysteria2 HK"]["hysteria2"] == {
        "sni": "hy2.example.com", "allow_insecure": False,
        "obfs": "salamander", "obfs_password": "shared",
    }


def test_subscription_routes_use_existing_pipeline(client, db):
    from app.utils.jwt import create_subscription_token
    user = make_user(db, tags="hk")
    make_node(db)
    token = create_subscription_token(user.username)
    response = client.get(f"/sub/{token}", headers={"User-Agent": "mihomo/1.0"})
    assert response.status_code == 200
    assert yaml.safe_load(response.text)["proxies"][0]["name"] == "HK"
    response = client.get(f"/sub/{token}/clash-meta")
    assert response.status_code == 200
    assert yaml.safe_load(response.text)["proxies"][0]["type"] == "hysteria2"


@pytest.mark.parametrize("tags", ["", "hk"])
@pytest.mark.parametrize("user_agent,meta", [
    ("ClashMetaForAndroid/2.11.18.Meta", True),
    ("ClashMeta/1.19.0", True),
    ("ClashForAndroid/2.5.12", False),
])
def test_android_subscription_exports_supported_protocols(client, db, monkeypatch, tags, user_agent, meta):
    from app.utils.jwt import create_subscription_token
    from app.xray.config import XRayConfig

    raw = json.loads(os.environ["XRAY_JSON"])
    tls_stream = {"network": "tcp", "security": "tls",
                  "tlsSettings": raw["inbounds"][1]["streamSettings"]["tlsSettings"]}
    raw["inbounds"][0]["streamSettings"] = tls_stream
    raw["inbounds"].append({
        "tag": "VLESS TLS", "protocol": "vless", "port": 8444,
        "settings": {"clients": []},
        "streamSettings": tls_stream,
    })
    monkeypatch.setattr(xray, "config", XRayConfig(raw))
    user = crud.create_user(db, UserCreate(
        username="alice", proxies={"trojan": {}, "vless": {}, "hysteria2": {}},
    ))
    user.sub_tags = tags
    user.sub_url_prefix = "https://sub.example.com" if tags else ""
    db.commit()
    for name, inbound, port in (("Trojan", "Trojan TCP", "8443"),
                                ("VLESS", "VLESS TLS", "8444"),
                                ("Hysteria2", "Hysteria2 HK", "443")):
        make_node(db, name=name, inbound=inbound, port=port)

    token = create_subscription_token(user.username)
    response = client.get(f"/sub/{token}", headers={"User-Agent": user_agent})
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/yaml")
    nodes = yaml.safe_load(response.text)["proxies"]
    assert {node["type"] for node in nodes} == ({"trojan", "vless", "hysteria2"} if meta else {"trojan"})


def test_node_round_trip_keeps_inheriting_and_can_restore_defaults(client, db, monkeypatch):
    user = make_user(db, tags="hk")
    payload = {"name": "HK", "server": "hy2.example.com", "port": "443", "tag": "hk",
               "inbound": "Hysteria2 HK", "settings": {"hidden": True}}
    response = client.post("/api/clash/proxy", json=payload)
    assert response.status_code == 200, response.text
    saved = response.json()
    assert saved["settings"] == {"hidden": True, "hysteria2": {}}
    assert client.put(f'/api/clash/proxy/{saved["id"]}', json=saved).status_code == 200
    option = ClashConfig.Option()
    option.support_hysteria2 = True
    defaults = xray.config.inbounds_by_tag["Hysteria2 HK"]["hysteria2"]

    def exported():
        return yaml.safe_load(generate_subscription_with_rules(db, user, "mihomo", option))["proxies"][0]

    for password in ("enabled-obfs", "rotated-obfs"):
        monkeypatch.setitem(defaults, "obfs", "salamander")
        monkeypatch.setitem(defaults, "obfs_password", password)
        assert exported()["obfs-password"] == password

    saved["settings"]["hysteria2"] = {"sni": "custom.example.com", "obfs": ""}
    response = client.put(f'/api/clash/proxy/{saved["id"]}', json=saved)
    assert response.status_code == 200, response.text
    assert response.json()["settings"]["hysteria2"] == saved["settings"]["hysteria2"]
    assert exported()["sni"] == "custom.example.com"
    assert "obfs" not in exported()

    saved["settings"]["hysteria2"] = {}
    assert client.put(f'/api/clash/proxy/{saved["id"]}', json=saved).status_code == 200
    assert exported()["obfs-password"] == "rotated-obfs"
    assert exported()["sni"] == defaults["sni"]
    assert crud.get_clash_proxy(db, saved["id"]).settings["hidden"] is True


def test_node_preserves_explicit_false_empty_and_null_overrides(db, monkeypatch):
    defaults = xray.config.inbounds_by_tag["Hysteria2 HK"]["hysteria2"]
    monkeypatch.setitem(defaults, "allow_insecure", True)
    monkeypatch.setitem(defaults, "up_mbps", 20)
    overrides = {"sni": "", "allow_insecure": False, "up_mbps": None}
    node = make_node(db, settings={"hysteria2": overrides})
    assert node.settings["hysteria2"] == overrides


@pytest.mark.parametrize("sans,expected", [
    (["127.0.0.1", "hy2.example.com"], "hy2.example.com"),
    (["*.hy2.example.com", "hy2.example.com"], "hy2.example.com"),
    (["127.0.0.1"], "127.0.0.1"),
    (["::1"], "::1"),
    ([], ""),
])
@pytest.mark.parametrize("server_name", ["", "explicit.example.com"])
def test_certificate_sans_and_explicit_sni(sans, expected, server_name):
    from conftest import key, subject
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from app.xray.config import XRayConfig

    names = []
    for name in sans:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            names.append(x509.DNSName(name))
    now = datetime.utcnow()
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1)))
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    raw = json.loads(os.environ["XRAY_JSON"])
    tls = next(i for i in raw["inbounds"] if i["protocol"] == "hysteria")["streamSettings"]["tlsSettings"]
    tls["certificates"] = [{"certificate": cert.public_bytes(serialization.Encoding.PEM).decode().splitlines()}]
    tls["serverName"] = server_name
    resolved = XRayConfig(raw).inbounds_by_tag["Hysteria2 HK"]
    assert resolved["hysteria2"]["sni"] == (server_name or expected)
    assert all(isinstance(name, str) for name in resolved["sni"])
    assert resolved["certificate_sha256"] == cert.fingerprint(hashes.SHA256()).hex()


@pytest.mark.parametrize("insecure", [False, True])
def test_native_json_uses_certificate_pin_instead_of_removed_allowinsecure(db, insecure):
    from app.subscription.hysteria2 import clash_node, share_link, singbox_outbound

    user = UserResponse.model_validate(make_user(db))
    host, = xray.hosts["Hysteria2 HK"]
    host["allowinsecure"] = insecure
    result = json.loads(generate_subscription(user, "v2ray-json", as_base64=False, reverse=False))
    outbound, = result[0]["outbounds"]
    tls = outbound["streamSettings"]["tlsSettings"]
    assert "allowInsecure" not in tls
    if insecure:
        assert tls["pinnedPeerCertSha256"] == xray.config.inbounds_by_tag["Hysteria2 HK"]["certificate_sha256"]
    else:
        assert "pinnedPeerCertSha256" not in tls
    node = clash_node("HK", "hy2.example.com", 443, "password", {"allow_insecure": insecure})
    assert node["skip-cert-verify"] is insecure
    assert singbox_outbound(node)["tls"]["insecure"] is insecure
    assert ("insecure" in parse_qs(urlsplit(share_link(node)).query)) is insecure


def test_native_json_requires_a_certificate_when_pinning():
    from app.subscription.hysteria2 import clash_node, xray_outbound
    node = clash_node("HK", "hy2.example.com", 443, "password", {"allow_insecure": True})
    with pytest.raises(ValueError, match="certificate SHA256"):
        xray_outbound(node)
