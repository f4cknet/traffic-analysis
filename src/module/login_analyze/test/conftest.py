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
    """helper: 构造一条 record"""
    def _make(ts_epoch, ip_src, method, host, uri, ua=""):
        from src.core import split_uri
        uri_path, uri_query = split_uri(uri)
        return {
            "ts_epoch": ts_epoch, "ip_src": ip_src,
            "method": method, "host": host,
            "uri": uri, "uri_path": uri_path, "uri_query": uri_query,
            "ua": ua, "headers": {},
            "payload_str": "",
        }
    return _make


@pytest.fixture
def attack_records(make_record):
    """模拟攻击者扫描多个登录后台 (112 条记录)"""
    attacker = "192.168.94.59"
    return [
        # 高频访问 /admin/login (50 次)
        *[make_record(1700000000 + i * 60, attacker, "GET", "target.com", f"/admin/login?id={i}")
          for i in range(50)],
        # 多次访问 /wp-login.php (20 次)
        *[make_record(1700001000 + i * 60, attacker, "POST", "target.com", "/wp-login.php")
          for i in range(20)],
        # 访问 /phpmyadmin (30 次)
        *[make_record(1700002000 + i * 60, attacker, "GET", "target.com", "/phpmyadmin/index.php")
          for i in range(30)],
        # 正常浏览器误报 (低频 1 次)
        make_record(1700003000, "192.168.32.100", "GET", "target.com", "/login"),
        # 另一个攻击者
        *[make_record(1700004000 + i * 60, "10.0.0.5", "GET", "target.com", "/manager/html")
          for i in range(10)],
    ]