"""Opt-in native-core checks: set XRAY_TEST_EXECUTABLE and optional XRAY_TEST_CERT_DIR."""

import json
import os
import socket
import subprocess
import threading
import time
from contextlib import closing
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import grpc
import pytest
import requests

from app import xray
from app.models.user import UserResponse
from app.subscription.share import generate_subscription
from app.xray.config import XRayConfig
from conftest import native_inbound
from test_hysteria2 import make_user
from xray_api import XRay
from xray_api.types import Hysteria2Account

pytestmark = pytest.mark.skipif(not os.getenv("XRAY_TEST_EXECUTABLE"), reason="native Xray checks are opt-in")


def free_port(kind=socket.SOCK_STREAM):
    with closing(socket.socket(socket.AF_INET, kind)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def native_server(obfs=False):
    inbound = deepcopy(native_inbound)
    inbound.update(listen="127.0.0.1", port=free_port(socket.SOCK_DGRAM))
    if cert_dir := os.getenv("XRAY_TEST_CERT_DIR"):
        inbound["streamSettings"]["tlsSettings"]["certificates"] = [{
            "certificateFile": str(Path(cert_dir, "fullchain.pem")),
            "keyFile": str(Path(cert_dir, "privkey.pem")),
        }]
    if obfs:
        inbound["streamSettings"]["finalmask"] = {
            "udp": [{"type": "salamander", "settings": {"password": "test-obfs-password"}}],
        }
    return XRayConfig({"inbounds": [inbound], "outbounds": [{"tag": "DIRECT", "protocol": "freedom"}]},
                     api_port=free_port())


def exported_client(db, monkeypatch, server, insecure):
    monkeypatch.setattr(xray, "config", server)
    user = make_user(db)
    host, = xray.hosts["Hysteria2 HK"]
    host.update(address=["127.0.0.1"], port=server.get_inbound("Hysteria2 HK")["port"],
                sni=[server.inbounds_by_tag["Hysteria2 HK"]["hysteria2"]["sni"]], allowinsecure=insecure)
    client, = json.loads(generate_subscription(UserResponse.model_validate(user), "v2ray-json",
                                              as_base64=False, reverse=False))
    client["inbounds"] = [{"tag": "SOCKS", "listen": "127.0.0.1", "port": free_port(),
                           "protocol": "socks", "settings": {"auth": "noauth"}}]
    return user, client


@pytest.mark.parametrize("insecure", [False, True])
@pytest.mark.parametrize("obfs", [False, True])
def test_exported_json_is_accepted_by_native_xray(db, monkeypatch, tmp_path, insecure, obfs):
    _, client = exported_client(db, monkeypatch, native_server(obfs), insecure)
    path = tmp_path / "client.json"
    path.write_text(json.dumps(client))
    result = subprocess.run([os.environ["XRAY_TEST_EXECUTABLE"], "run", "-test", "-config", str(path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hysteria2-native-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.mark.parametrize("obfs", [False, True])
@pytest.mark.parametrize("insecure", [False, True])
def test_native_auth_tls_traffic_and_remove(db, monkeypatch, tmp_path, insecure, obfs):
    if not insecure and not os.getenv("XRAY_TEST_CERT_DIR"):
        pytest.skip("standard TLS verification requires a trusted certificate")
    processes = []
    logs = []
    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    def start(name, config):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(config))
        log = (tmp_path / f"{name}.log").open("w+")
        logs.append(log)
        process = subprocess.Popen([os.environ["XRAY_TEST_EXECUTABLE"], "run", "-config", str(path)],
                                   stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def wait_for_socks(port):
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    return
            except OSError:
                time.sleep(.05)
        pytest.fail("client SOCKS listener did not start")

    try:
        server = native_server(obfs)
        # Latest Xray blocks private targets by default. Allow only this test's HTTP endpoint.
        server["outbounds"][0]["settings"] = {"finalRules": [{
            "action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"], "port": str(target.server_port),
        }]}
        user, client = exported_client(db, monkeypatch, server, insecure)
        start("server", server)
        api = XRay(server.api_host, server.api_port)
        grpc.channel_ready_future(api._channel).result(timeout=5)
        email = f"{user.id}.{user.username}"
        assert api.add_inbound_user("Hysteria2 HK", Hysteria2Account(
            email=email, password=user.proxies[0].settings["password"]), timeout=5)
        process = start("client", client)
        socks_port = client["inbounds"][0]["port"]
        wait_for_socks(socks_port)
        proxy = {"http": f"socks5h://127.0.0.1:{socks_port}"}
        url = f"http://127.0.0.1:{target.server_port}/"
        response = requests.get(url, proxies=proxy, timeout=5)
        assert response.status_code == 200
        assert response.content == b"hysteria2-native-ok"
        stats = list(api.get_users_stats(timeout=5))
        assert sum(stat.value for stat in stats if stat.name == email) > 0
        assert api.remove_inbound_user("Hysteria2 HK", email, timeout=5)
        process.terminate()
        process.wait(timeout=3)
        start("fresh-client", client)
        wait_for_socks(socks_port)
        with pytest.raises(requests.RequestException):
            requests.get(url, proxies=proxy, timeout=2)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        target.shutdown()
        target.server_close()
        for log in logs:
            log.close()
