"""credential_analyze/test - pytest 单测

测 src.module.credential_analyze.script 业务逻辑:
  - parse_urlencoded_body: urlencoded POST body 解析
  - extract_credentials_from_request: 单条记录凭证提取
  - aggregate_by_credential / build_attacker_profiles: 聚合
  - is_suspicious_login_success: 状态码过滤

不依赖 pcap / 网络, 纯 dict fixture.
"""
import sys
from pathlib import Path

import pytest

# 把项目根 (analyzer-toolkit/) 加进 sys.path
_PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(_PROJECT_ROOT))

from src.module.login_analyze.script import load_rules


@pytest.fixture(scope="session")
def paths_data():
    """复用 login-analyze 的 login_paths.yaml"""
    yaml_path = _PROJECT_ROOT / "src" / "module" / "login_analyze" / "rules" / "login_paths.yaml"
    return load_rules(yaml_path)


def _make_post_record(ts_epoch, ip_src, uri, body_bytes, content_type="application/x-www-form-urlencoded",
                       status=None, stream_id="0"):
    """构造 POST record with body. status 写到 responses_by_stream (caller 关联)."""
    from src.core import split_uri
    uri_path, uri_query = split_uri(uri)
    return {
        "kind": "request",
        "ts_epoch": ts_epoch,
        "ip_src": ip_src,
        "stream_id": stream_id,
        "method": "POST",
        "host": "target.com",
        "uri": uri,
        "uri_path": uri_path,
        "uri_query": uri_query,
        "ua": "Mozilla/5.0 (Windows NT 10.0)",
        "headers": {},
        "content_type": content_type,
        "post_body_bytes": body_bytes,
        "payload_str": uri_path,
    }, status  # tuple


@pytest.fixture
def attack_http_data():
    """
    模拟攻击者登录尝试 — 含正常 / 可疑 / 失败 三种情况.

    设计:
      - 192.168.94.59 (主攻) POST /admin/login.php x5
          admin/admin123 (200 高度可疑)
          admin/qwerty (302 真登录成功)
          admin/123456 (200)
          root/toor (200)
          admin/1234 (404 失败, 不计)
      - 192.168.94.59 POST /wp-login.php x2
          admin/password (302)
          admin/admin (200)
      - 192.168.94.233 (伴攻) POST /admin/login.php x1
          test/test123 (200)
      - 192.168.32.100 (正常用户) POST /login x1
          user1/mypass (200)
      - 1 条 GET /admin/login.php (扫描表单页, 不算登录尝试)
    """
    requests = []
    responses = {}

    # 主攻 admin/admin123 → 200
    sid = "s1"
    rec, _ = _make_post_record(
        1700000000, "192.168.94.59",
        "/admin/login.php?rec=login",
        b"username=admin&password=admin123",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 200

    # admin/qwerty → 302 (金标准登录成功)
    sid = "s2"
    rec, _ = _make_post_record(
        1700000060, "192.168.94.59",
        "/admin/login.php?rec=login",
        b"username=admin&password=qwerty",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 302

    # admin/123456 → 200
    sid = "s3"
    rec, _ = _make_post_record(
        1700000120, "192.168.94.59",
        "/admin/login.php?rec=login",
        b"username=admin&password=123456",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 200

    # root/toor → 200
    sid = "s4"
    rec, _ = _make_post_record(
        1700000180, "192.168.94.59",
        "/admin/login.php?rec=login",
        b"username=root&password=toor",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 200

    # admin/1234 → 404 (失败, 不计)
    sid = "s5"
    rec, _ = _make_post_record(
        1700000240, "192.168.94.59",
        "/admin/login.php?rec=login",
        b"username=admin&password=1234",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 404

    # wp-login admin/password → 302
    sid = "s6"
    rec, _ = _make_post_record(
        1700000300, "192.168.94.59",
        "/wp-login.php",
        b"log=admin&pwd=password&wp-submit=Log+In",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 302

    # wp-login admin/admin → 200
    sid = "s7"
    rec, _ = _make_post_record(
        1700000360, "192.168.94.59",
        "/wp-login.php",
        b"log=admin&pwd=admin",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 200

    # 伴攻 test/test123 → 200
    sid = "s8"
    rec, _ = _make_post_record(
        1700000420, "192.168.94.233",
        "/admin/login.php?rec=login",
        b"username=test&password=test123",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 200

    # 正常用户 user1/mypass → 200
    sid = "s9"
    rec, _ = _make_post_record(
        1700000500, "192.168.32.100",
        "/login",
        b"username=user1&password=mypass",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 200

    # GET 表单页扫描 — 不算登录尝试
    sid = "s10"
    rec = {
        "kind": "request",
        "ts_epoch": 1700000600,
        "ip_src": "192.168.94.59",
        "stream_id": sid,
        "method": "GET",
        "host": "target.com",
        "uri": "/admin/login.php",
        "uri_path": "/admin/login.php",
        "uri_query": "",
        "ua": "Mozilla/5.0",
        "headers": {},
        "content_type": "",
        "post_body_bytes": b"",
        "payload_str": "/admin/login.php",
    }
    requests.append(rec)
    responses[sid] = 200

    # POST 但 body 不是 urlencoded (multipart) — v0.4.0 不支持
    sid = "s11"
    rec, _ = _make_post_record(
        1700000660, "192.168.94.59",
        "/admin/login.php",
        b"--boundary\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nadmin\r\n--boundary--",
        content_type="multipart/form-data; boundary=boundary",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 200

    # POST 但 body 完全空 — 失败
    sid = "s12"
    rec, _ = _make_post_record(
        1700000720, "192.168.94.59",
        "/admin/login.php",
        b"",
        stream_id=sid,
    )
    requests.append(rec)
    responses[sid] = 200

    return {
        "requests": requests,
        "responses_by_stream": responses,
    }