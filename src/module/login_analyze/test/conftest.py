"""login_analyze/test - pytest 单测

紧耦合 module, 测 src.module.login_analyze.script 业务逻辑.
不依赖 pcap / 网络.
"""
import sys
from pathlib import Path

import pytest

# 把项目根 (analyzer-toolkit/) 加进 sys.path, 这样 `src.module.xxx` 才能 import
_PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(_PROJECT_ROOT))

from src.module.login_analyze.script import load_rules


@pytest.fixture(scope="session")
def paths_data():
    """项目自带的 login_paths.yaml"""
    yaml_path = _PROJECT_ROOT / "src" / "module" / "login_analyze" / "rules" / "login_paths.yaml"
    return load_rules(yaml_path)


@pytest.fixture
def make_record():
    """helper: 构造一条 request record (含 stream_id)"""
    def _make(ts_epoch, ip_src, method, host, uri, ua="", stream_id="0"):
        from src.core import split_uri
        uri_path, uri_query = split_uri(uri)
        return {
            "kind": "request",
            "ts_epoch": ts_epoch, "ip_src": ip_src, "stream_id": stream_id,
            "method": method, "host": host,
            "uri": uri, "uri_path": uri_path, "uri_query": uri_query,
            "ua": ua, "headers": {},
            "payload_str": "",
        }
    return _make


def _http_data(requests, responses=None):
    """helper: 构造 http_data 字典"""
    return {
        "requests": requests,
        "responses_by_stream": responses or {},
    }


@pytest.fixture
def attack_http_data(make_record):
    """模拟攻击者扫描 + 混合响应状态"""
    attacker = "192.168.94.59"
    requests = []
    responses = {}

    # /admin/login 50 次 (假设全 200 真存在)
    for i in range(50):
        sid = f"stream_{i}"
        requests.append(make_record(
            1700000000 + i * 60, attacker, "GET", "target.com",
            f"/admin/login?id={i}", stream_id=sid,
        ))
        responses[sid] = 200

    # /wp-login.php 20 次 (全 200)
    for i in range(20):
        sid = f"stream_wp_{i}"
        requests.append(make_record(
            1700001000 + i * 60, attacker, "POST", "target.com",
            "/wp-login.php", stream_id=sid,
        ))
        responses[sid] = 200

    # /phpmyadmin 30 次 (全 200)
    for i in range(30):
        sid = f"stream_pma_{i}"
        requests.append(make_record(
            1700002000 + i * 60, attacker, "GET", "target.com",
            "/phpmyadmin/index.php", stream_id=sid,
        ))
        responses[sid] = 200

    # /admin/nonexistent 50 次 (404, 探测失败, 应被过滤)
    for i in range(50):
        sid = f"stream_404_{i}"
        requests.append(make_record(
            1700002500 + i * 60, attacker, "GET", "target.com",
            "/admin/nonexistent.php", stream_id=sid,
        ))
        responses[sid] = 404

    # 正常浏览器误报 1 次 (login_generic 200)
    requests.append(make_record(
        1700003000, "192.168.32.100", "GET", "target.com",
        "/login", stream_id="stream_normal",
    ))
    responses["stream_normal"] = 200

    # 另一个攻击者
    for i in range(10):
        sid = f"stream_tom_{i}"
        requests.append(make_record(
            1700004000 + i * 60, "10.0.0.5", "GET", "target.com",
            "/manager/html", stream_id=sid,
        ))
        responses[sid] = 200

    return _http_data(requests, responses)