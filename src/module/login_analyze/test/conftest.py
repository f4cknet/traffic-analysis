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
    """helper: 构造一条 request record (含 stream_id + method)"""
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
    """模拟攻击者扫描 + 混合方法/状态.

    设计原则:
      - 真"尝试登录"用 POST (rule.methods=[POST] 才会命中)
      - GET 也保留部分 (模拟攻击者扫描 GET 表单页, 但不被算作登录尝试)
      - 部分响应 404 (模拟探测失败, 应被状态过滤掉)
      - 多 IP 跨账户画像
    """
    attacker = "192.168.94.59"
    requests = []
    responses = {}

    # 50 次 POST /admin/login (真尝试登录, 200 真存在) → 应计
    for i in range(50):
        sid = f"stream_admin_{i}"
        requests.append(make_record(
            1700000000 + i * 60, attacker, "POST", "target.com",
            f"/admin/login?id={i}", stream_id=sid,
        ))
        responses[sid] = 200

    # 20 次 POST /wp-login.php (wordpress, [GET, POST] 允许, 200) → 应计
    for i in range(20):
        sid = f"stream_wp_{i}"
        requests.append(make_record(
            1700001000 + i * 60, attacker, "POST", "target.com",
            "/wp-login.php", stream_id=sid,
        ))
        responses[sid] = 200

    # 10 次 GET /wp-login.php (扫描表单页, 但 wordpress 允许 GET, 200) → 应计
    for i in range(10):
        sid = f"stream_wp_get_{i}"
        requests.append(make_record(
            1700001200 + i * 60, attacker, "GET", "target.com",
            "/wp-login.php", stream_id=sid,
        ))
        responses[sid] = 200

    # 30 次 POST /phpmyadmin/index.php (pma 允许 GET+POST, 200) → 应计
    for i in range(30):
        sid = f"stream_pma_{i}"
        requests.append(make_record(
            1700002000 + i * 60, attacker, "POST", "target.com",
            "/phpmyadmin/index.php", stream_id=sid,
        ))
        responses[sid] = 200

    # 20 次 GET /login (扫描表单, 但 login_generic 只允许 POST, 200) → 应被过滤
    for i in range(20):
        sid = f"stream_login_get_{i}"
        requests.append(make_record(
            1700003000 + i * 60, attacker, "GET", "target.com",
            "/login", stream_id=sid,
        ))
        responses[sid] = 200

    # 50 次 POST /admin/login 404 (探测失败) → 应被状态过滤
    for i in range(50):
        sid = f"stream_404_{i}"
        requests.append(make_record(
            1700002500 + i * 60, attacker, "POST", "target.com",
            "/admin/login.php", stream_id=sid,
        ))
        responses[sid] = 404

    # 1 次 POST /login 真登录 (另一个 IP, 200) → 应计
    requests.append(make_record(
        1700004000, "192.168.32.100", "POST", "target.com",
        "/login", stream_id="stream_normal",
    ))
    responses["stream_normal"] = 200

    # 10 次 POST /user/login (Drupal, 200) → 应计
    for i in range(10):
        sid = f"stream_drupal_{i}"
        requests.append(make_record(
            1700005000 + i * 60, "10.0.0.5", "POST", "target.com",
            "/user/login", stream_id=sid,
        ))
        responses[sid] = 200

    return _http_data(requests, responses)
