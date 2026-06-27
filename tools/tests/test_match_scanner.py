"""test_match_scanner.py - 测三段式匹配逻辑"""
import pytest

from analyzer_core import match_scanner


def _hit_for(rules, request, scanner_id: str):
    """辅助: 拿指定扫描器对 request 的命中结果 (单条)"""
    hits = match_scanner(request, rules)
    for sc, segs, w in hits:
        if sc["id"] == scanner_id:
            return (sc, segs, w)
    return None


# ============== UA 段触发 ==============

def test_match_awvs_header_segment(rules, awvs_request):
    """AWVS 主要靠 header 段触发 (Acunetix-Aspect)"""
    hit = _hit_for(rules, awvs_request, "acunetix_wvs")
    assert hit is not None
    sc, segs, w = hit
    assert "header" in segs, f"应触发 header 段, 实际: {segs}"


def test_match_awvs_payload_segment(rules, awvs_request):
    """AWVS 的 payload_keywords (uri 中含 'acunetix' 不在 fixture 里, 但 header 段匹配会触发)

    fixture 里没 payload 中的 acunetix 关键字, 所以只验证 header 段命中"""
    hit = _hit_for(rules, awvs_request, "acunetix_wvs")
    assert hit is not None
    # 没有 uri 含 'acunetix', 不会触发 payload 段
    assert "payload" not in hit[1]


def test_match_sqlmap_ua_segment(rules, sqlmap_request):
    """sqlmap UA 自带版本号, 应触发 ua 段"""
    hit = _hit_for(rules, sqlmap_request, "sqlmap")
    assert hit is not None
    sc, segs, w = hit
    assert "ua" in segs
    # sqlmap UA 是强证据, weight 应 >= 10
    assert w >= 10


def test_match_nessus_ua_segment(rules, nessus_request):
    """nessus UA 'Nessus SOAP' 应触发 ua 段"""
    hit = _hit_for(rules, nessus_request, "nessus")
    assert hit is not None
    sc, segs, w = hit
    assert "ua" in segs


def test_match_normal_browser_no_hit(rules, normal_browser_request):
    """正常 Chrome 浏览器请求不应触发任何扫描器"""
    hits = match_scanner(normal_browser_request, rules)
    assert hits == [], f"正常浏览器意外触发: {[h[0]['id'] for h in hits]}"


def test_match_xff_injector(rules, awvs_request):
    """带 X-Forwarded-For 的请求应触发 xff_injector (header 段)"""
    hit = _hit_for(rules, awvs_request, "xff_injector")
    assert hit is not None
    sc, segs, w = hit
    assert "header" in segs


def test_match_returns_sorted_results(rules, mixed_records):
    """match_scanner 返回 [(sc, segs, w), ...] 列表"""
    for rec in mixed_records:
        hits = match_scanner(rec, rules)
        for item in hits:
            assert len(item) == 3, "返回项应是 (scanner, segments, weight) 三元组"
            assert isinstance(item[1], list)  # segments 是 list
            assert isinstance(item[2], int)    # weight 是 int


def test_match_weight_accumulation(rules, awvs_request):
    """weight 应按段累加: header(12) + 可能的 payload(1)"""
    hit = _hit_for(rules, awvs_request, "acunetix_wvs")
    assert hit is not None
    sc, segs, w = hit
    # fixture 中 header 段必触发 (Acunetix-Aspect)
    # payload 段不触发 (uri 不含 'acunetix')
    assert w == sc["weight"]["header"], f"header 段 weight 累加错误: {w}"


# ============== 边界情况 ==============

def test_match_empty_ua(rules):
    """空 UA 不应崩溃, 也不应误触发"""
    rec = {
        "ts_epoch": 0, "ip_src": "1.2.3.4", "method": "GET",
        "host": "x.com", "uri": "/", "ua": "",
        "headers": {"Host": "x.com"}, "payload_str": "/ x.com GET",
    }
    hits = match_scanner(rec, rules)
    # UA 段全不触发
    for sc, segs, w in hits:
        assert "ua" not in segs


def test_match_payload_only_weak(rules):
    """payload 段单独命中应是弱辅证 (weight 较小)"""
    # 构造一条 URI 含 acunetix 但 UA/header 都是正常的请求
    rec = {
        "ts_epoch": 0, "ip_src": "1.2.3.4", "method": "GET",
        "host": "x.com", "uri": "/?id=$acunetix=1",
        "ua": "Mozilla/5.0 Chrome/120.0",
        "headers": {"Host": "x.com", "User-Agent": "Mozilla/5.0 Chrome/120.0"},
        "payload_str": "/?id=$acunetix=1 Mozilla/5.0 Chrome/120.0 x.com GET",
    }
    hit = _hit_for(rules, rec, "acunetix_wvs")
    assert hit is not None
    sc, segs, w = hit
    # 应只触发 payload 段 (无 UA / header 命中)
    assert segs == ["payload"], f"应只 payload 段, 实际: {segs}"
    assert w == sc["weight"]["payload"]  # 仅 payload 段 weight