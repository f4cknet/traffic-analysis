"""scanner-analyze/test - pytest 单测

紧耦合 module, 测 src.module.scanner-analyze.script 业务逻辑.
不依赖 pcap / 网络.
"""
import sys
from pathlib import Path

import pytest

# 把项目根 (analyzer-toolkit/) 加进 sys.path, 这样 `src.module.xxx` 才能 import
_PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(_PROJECT_ROOT))

from src.module.scanner_analyze.script import (
    aggregate_per_ip_scanners,
    analyze,
    load_rules,
    match_scanner,
    print_summary,
)


@pytest.fixture(scope="session")
def rules():
    """项目自带的 scanners.yaml"""
    yaml_path = _PROJECT_ROOT / "src" / "module" / "scanner_analyze" / "rules" / "scanners.yaml"
    return load_rules(yaml_path)


def _make_record(ts_epoch, ip_src, method, host, uri, ua, headers):
    """
    helper: 构造一条 record, 自动拆 URI path/query, 算 payload_str (不含 query)

    payload_str contract: URI path + UA + host + method (剔除 query, 防诱导)
    """
    from src.core import split_uri
    uri_path, uri_query = split_uri(uri)
    payload_str = " ".join([uri_path, ua, host, method])
    return {
        "ts_epoch": ts_epoch, "ip_src": ip_src,
        "method": method, "host": host,
        "uri": uri, "uri_path": uri_path, "uri_query": uri_query,
        "ua": ua, "headers": headers,
        "payload_str": payload_str,
    }


@pytest.fixture
def awvs_request():
    """AWVS 强证据: Acunetix-Aspect header + Chrome 41 伪装 UA"""
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/41.0.2228.0"
    return _make_record(
        ts_epoch=1700000000.0, ip_src="192.168.94.59",
        method="GET", host="192.168.32.189",
        uri="/some/path?id=1", ua=ua,
        headers={
            "Host": "192.168.32.189", "User-Agent": ua, "Accept": "*/*",
            "Acunetix-Aspect": "enabled",
            "Acunetix-Aspect-Password": "082119f75623eb7abd7bf357698ff66c",
            "X-Forwarded-For": "1.2.3.4",
        },
    )


@pytest.fixture
def sqlmap_request():
    """sqlmap 强证据: UA 自带版本号"""
    ua = "sqlmap/1.2.3.50#dev (http://sqlmap.org)"
    return _make_record(
        ts_epoch=1700000001.0, ip_src="192.168.94.59",
        method="GET", host="192.168.32.189",
        uri="/?id=1", ua=ua,
        headers={"Host": "192.168.32.189", "User-Agent": ua},
    )


@pytest.fixture
def nessus_request():
    """nessus UA 强证据"""
    return _make_record(
        ts_epoch=1700000002.0, ip_src="10.0.0.5",
        method="GET", host="192.168.32.189",
        uri="/", ua="Nessus SOAP",
        headers={"Host": "192.168.32.189", "User-Agent": "Nessus SOAP"},
    )


@pytest.fixture
def normal_browser_request():
    """正常 Chrome 浏览器请求, 不应触发任何扫描器"""
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    return _make_record(
        ts_epoch=1700000003.0, ip_src="192.168.32.100",
        method="GET", host="example.com",
        uri="/index.html", ua=ua,
        headers={
            "Host": "example.com", "User-Agent": ua,
            "Accept": "text/html", "Accept-Language": "zh-CN,zh;q=0.9",
        },
    )


@pytest.fixture
def mixed_records(awvs_request, sqlmap_request, nessus_request, normal_browser_request):
    """6 条不同特征记录的混合 (AWVS x3 + sqlmap + nessus + 正常)"""
    records = [
        awvs_request,
        {**awvs_request, "ts_epoch": 1700000010.0, "uri": "/another/path?id=2"},
        {**awvs_request, "ts_epoch": 1700000020.0, "uri": "/third"},
        sqlmap_request,
        nessus_request,
        normal_browser_request,
    ]
    # 新接口: analyze() 接 http_data = {"requests": [...], "responses_by_stream": {...}}
    return {"requests": records, "responses_by_stream": {}}