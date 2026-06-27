"""共享 fixture: 扫描器规则 + sample records"""
import sys
from pathlib import Path

import pytest

# 把 src/ 加进 path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from analyzer_core import load_rules


@pytest.fixture(scope="session")
def rules():
    """项目自带的 scanners.yaml"""
    yaml_path = Path(__file__).resolve().parents[1] / "rules" / "scanners.yaml"
    return load_rules(yaml_path)


@pytest.fixture
def awvs_request():
    """一条带 Acunetix-Aspect header 的请求 (AWVS 强证据)"""
    return {
        "ts_epoch": 1700000000.0,
        "ip_src": "192.168.94.59",
        "method": "GET",
        "host": "192.168.32.189",
        "uri": "/some/path?id=1",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/41.0.2228.0",
        "headers": {
            "Host": "192.168.32.189",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/41.0.2228.0",
            "Accept": "*/*",
            "Acunetix-Aspect": "enabled",
            "Acunetix-Aspect-Password": "082119f75623eb7abd7bf357698ff66c",
            "X-Forwarded-For": "1.2.3.4",
        },
        "payload_str": "/some/path?id=1 Mozilla/5.0 ... 192.168.32.189 GET",
    }


@pytest.fixture
def sqlmap_request():
    """一条 sqlmap 特征 UA 请求 (UA 强证据)"""
    return {
        "ts_epoch": 1700000001.0,
        "ip_src": "192.168.94.59",
        "method": "GET",
        "host": "192.168.32.189",
        "uri": "/?id=1",
        "ua": "sqlmap/1.2.3.50#dev (http://sqlmap.org)",
        "headers": {
            "Host": "192.168.32.189",
            "User-Agent": "sqlmap/1.2.3.50#dev (http://sqlmap.org)",
        },
        "payload_str": "/?id=1 sqlmap/1.2.3.50#dev (http://sqlmap.org) 192.168.32.189 GET",
    }


@pytest.fixture
def nessus_request():
    """一条 nessus 特征 UA 请求 (UA 强证据)"""
    return {
        "ts_epoch": 1700000002.0,
        "ip_src": "10.0.0.5",
        "method": "GET",
        "host": "192.168.32.189",
        "uri": "/",
        "ua": "Nessus SOAP",
        "headers": {
            "Host": "192.168.32.189",
            "User-Agent": "Nessus SOAP",
        },
        "payload_str": "/ Nessus SOAP 192.168.32.189 GET",
    }


@pytest.fixture
def normal_browser_request():
    """一条正常 Chrome 浏览器请求 (不应触发任何扫描器)"""
    return {
        "ts_epoch": 1700000003.0,
        "ip_src": "192.168.32.100",
        "method": "GET",
        "host": "example.com",
        "uri": "/index.html",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "headers": {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html",
            "Accept-Language": "zh-CN,zh;q=0.9",
        },
        "payload_str": "/index.html Mozilla/5.0 ... example.com GET",
    }


@pytest.fixture
def mixed_records(awvs_request, sqlmap_request, nessus_request, normal_browser_request):
    """4 条不同特征记录的混合"""
    # 复制 awvs_request 出 3 份 (模拟攻击者多次发 AWVS 请求)
    records = [
        awvs_request,
        {**awvs_request, "ts_epoch": 1700000010.0, "uri": "/another/path"},
        {**awvs_request, "ts_epoch": 1700000020.0, "uri": "/third"},
        sqlmap_request,
        nessus_request,
        normal_browser_request,
    ]
    return records