"""Hysteria 2 client configuration shared by both subscription pipelines."""

from ipaddress import ip_address
from urllib.parse import quote, urlencode


def clash_node(name, server, port, password, options):
    node = {
        "name": name, "type": "hysteria2", "server": server, "port": int(port),
        "password": password, "sni": options.get("sni") or server,
        "skip-cert-verify": options.get("allow_insecure", False),
    }
    if options.get("obfs"):
        node.update({"obfs": options["obfs"], "obfs-password": options["obfs_password"]})
    for key, target in (("up_mbps", "up"), ("down_mbps", "down")):
        if options.get(key):
            node[target] = options[key]
    return node


def share_link(node):
    server = node["server"].strip("[]")
    try:
        if ip_address(server).version == 6:
            server = f"[{server}]"
    except ValueError:
        pass
    query = {"sni": node.get("sni") or node["server"]}
    if node.get("skip-cert-verify"):
        query["insecure"] = "1"
    if node.get("obfs"):
        query.update({"obfs": node["obfs"], "obfs-password": node["obfs-password"]})
    return (
        f'hysteria2://{quote(node["password"], safe="")}@{server}:{node["port"]}/'
        f'?{urlencode(query)}#{quote(node["name"], safe="")}'
    )


def singbox_outbound(node):
    outbound = {
        "type": "hysteria2", "tag": node["name"], "server": node["server"],
        "server_port": node["port"], "password": node["password"],
        "tls": {"enabled": True, "server_name": node["sni"],
                "insecure": node["skip-cert-verify"]},
    }
    if node.get("obfs"):
        outbound["obfs"] = {"type": node["obfs"], "password": node["obfs-password"]}
    for key in ("up", "down"):
        if node.get(key):
            outbound[f"{key}_mbps"] = node[key]
    return outbound


def xray_outbound(node, certificate_sha256=""):
    tls = {"serverName": node["sni"], "alpn": ["h3"]}
    if node["skip-cert-verify"]:
        if not certificate_sha256:
            raise ValueError("Hysteria 2 Xray certificate pinning requires an inbound certificate SHA256")
        tls["pinnedPeerCertSha256"] = certificate_sha256
    stream = {
        "network": "hysteria", "security": "tls",
        "tlsSettings": tls,
        "hysteriaSettings": {"version": 2, "auth": node["password"]},
    }
    finalmask = {}
    if node.get("obfs"):
        finalmask["udp"] = [{"type": "salamander", "settings": {"password": node["obfs-password"]}}]
    bandwidth = {f"brutal{key.title()}": f"{node[key]} mbps" for key in ("up", "down") if node.get(key)}
    if bandwidth:
        finalmask["quicParams"] = bandwidth
    if finalmask:
        stream["finalmask"] = finalmask
    return {
        "tag": "proxy", "protocol": "hysteria",
        "settings": {"version": 2, "address": node["server"], "port": node["port"]},
        "streamSettings": stream,
    }
