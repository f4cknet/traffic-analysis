"""webshell_analyze/test - pytest 单测

测 src.module.webshell_analyze.script 业务逻辑:
  - load_paths / match_webshell_path: yaml 加载 + 路径匹配
  - parse_multipart_filename: multipart body 解析
  - is_multipart_upload: Content-Type 判定
  - extract_url_query / extract_urlencoded_params: 参数提取
  - collect_uploads / collect_accesses / link_uploads_to_accesses: 聚合
  - field_aliases: yaml 字段别名

不依赖 pcap / 网络, 纯 dict fixture.
"""
import sys
from pathlib import Path

import pytest

# 把项目根加进 sys.path
_PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(_PROJECT_ROOT))

from src.module.webshell_analyze.script import load_paths


@pytest.fixture(scope="session")
def paths_data():
    """项目自带的 webshell_paths.yaml"""
    yaml_path = _PROJECT_ROOT / "src" / "module" / "webshell_analyze" / "rules" / "webshell_paths.yaml"
    return load_paths(yaml_path)


@pytest.fixture(scope="session")
def field_aliases():
    """项目自带的 webshell_fields.yaml"""
    from src.module.webshell_analyze.script import load_field_aliases
    yaml_path = _PROJECT_ROOT / "src" / "module" / "webshell_analyze" / "rules" / "webshell_fields.yaml"
    return load_field_aliases(yaml_path)


def _make_post_record(ts_epoch, ip_src, method, uri, body_bytes=b"",
                       content_type="", ua="", stream_id="0"):
    from src.core import split_uri
    uri_path, uri_query = split_uri(uri)
    return {
        "kind": "request",
        "ts_epoch": ts_epoch,
        "ip_src": ip_src,
        "stream_id": stream_id,
        "method": method,
        "host": "target.com",
        "uri": uri,
        "uri_path": uri_path,
        "uri_query": uri_query,
        "ua": ua,
        "headers": {},
        "content_type": content_type,
        "post_body_bytes": body_bytes,
        "payload_str": uri_path,
    }


# ============== Fixture: 完整 webshell 攻击场景 ==============

MULTIPART_BODY_HELLO_HTML = (
    b"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
    b'Content-Disposition: form-data; name="file"; filename="hello.html"\r\n'
    b"Content-Type: text/html\r\n"
    b"\r\n"
    b"<html><body>webshell test</body></html>\r\n"
    b"------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
)


@pytest.fixture
def attack_http_data():
    """
    模拟完整 webshell 攻击场景:
      - 14:00:00 攻击者上传 hello.html 到 /upload/
      - 14:01:00-14:03:00 攻击者多次访问 hello.html, 用 pass + cmd 参数
      - 14:02:00 攻击者访问 /shell.php (通用 PHP webshell 名) — 没上传, orphan
      - 14:05:00 攻击者访问 /upload/image.jpg (普通上传目录访问, 但非 webshell 后缀) — 不命中

    期望:
      - 1 条 upload (filename=hello.html)
      - 5 条 access (3 条 hello.html 关联 + 1 条 /shell.php orphan + 1 条 image.jpg 不命中)
      - 1 条 link (filename=hello.html, 3 个后续访问)
      - 1 条 orphan (/shell.php)
    """
    requests = []

    # 1. 上传 hello.html
    requests.append(_make_post_record(
        1700000000, "192.168.94.59", "POST",
        "/upload/upload.php",
        body_bytes=MULTIPART_BODY_HELLO_HTML,
        content_type="multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
        ua="Mozilla/5.0", stream_id="up1",
    ))

    # 2-4. 访问 hello.html (3 次, 不同 cmd)
    requests.append(_make_post_record(
        1700000060, "192.168.94.59", "POST",
        "/upload/hello.html",
        body_bytes=b"pass=cmdtest&cmd=whoami",
        content_type="application/x-www-form-urlencoded",
        ua="Mozilla/5.0", stream_id="a1",
    ))
    requests.append(_make_post_record(
        1700000120, "192.168.94.59", "GET",
        "/upload/hello.html?pass=cmdtest&cmd=id",
        content_type="", ua="Mozilla/5.0", stream_id="a2",
    ))
    requests.append(_make_post_record(
        1700000180, "192.168.94.59", "POST",
        "/upload/hello.html",
        body_bytes=b"pass=cmdtest&cmd=cat+/etc/passwd",
        content_type="application/x-www-form-urlencoded",
        ua="Mozilla/5.0", stream_id="a3",
    ))

    # 5. 访问 /shell.php (通用 PHP webshell 名 — 命中 generic_php rule, orphan)
    requests.append(_make_post_record(
        1700000300, "192.168.94.59", "POST",
        "/shell.php",
        body_bytes=b"pass=xxx&cmd=id",
        content_type="application/x-www-form-urlencoded",
        ua="Mozilla/5.0", stream_id="a4",
    ))

    # 6. 普通 upload 目录访问 (image.jpg 不命中)
    requests.append(_make_post_record(
        1700000400, "192.168.94.59", "GET",
        "/upload/image.jpg",
        body_bytes=b"", content_type="", ua="Mozilla/5.0", stream_id="a5",
    ))

    # 7. 跟攻击无关的请求 (不命中任何规则)
    requests.append(_make_post_record(
        1700000500, "192.168.94.59", "GET",
        "/index.html",
        body_bytes=b"", content_type="", ua="Mozilla/5.0", stream_id="a6",
    ))

    return {"requests": requests, "responses_by_stream": {}}