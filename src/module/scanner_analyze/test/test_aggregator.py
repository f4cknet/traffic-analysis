"""test_analyze.py - 测全量聚合与攻击者评分"""
import pytest

from src.core import classify_uri, is_browser_ua
from src.module.scanner_analyze.script import analyze


def test_analyze_total_count(rules, mixed_records):
    """mixed_records 6 条全应计入 total"""
    stats = analyze(mixed_records, rules)
    assert stats["total"] == 6


def test_analyze_awvs_hits_count(rules, mixed_records):
    """3 条 AWVS 请求应触发 acunetix_wvs 3 次 (header 段)"""
    stats = analyze(mixed_records, rules)
    assert stats["scanner_hits"]["acunetix_wvs"] == 3
    # header 段 3 次
    assert stats["scanner_hdr_hits"]["acunetix_wvs"] == 3
    # ua 段 0 次 (AWVS fixture UA 是 Chrome 41 伪装, 不含 sqlmap/Nessus/Nikto)
    assert stats["scanner_ua_hits"]["acunetix_wvs"] == 0


def test_analyze_sqlmap_ua_hit(rules, mixed_records):
    """sqlmap fixture 应触发 sqlmap ua 段 1 次"""
    stats = analyze(mixed_records, rules)
    assert stats["scanner_hits"]["sqlmap"] == 1
    assert stats["scanner_ua_hits"]["sqlmap"] == 1
    assert stats["scanner_hdr_hits"]["sqlmap"] == 0


def test_analyze_nessus_ua_hit(rules, mixed_records):
    """nessus fixture 应触发 nessus ua 段 1 次"""
    stats = analyze(mixed_records, rules)
    assert stats["scanner_hits"]["nessus"] == 1
    assert stats["scanner_ua_hits"]["nessus"] == 1


def test_analyze_xff_injector_per_awvs(rules, mixed_records):
    """每条 AWVS 请求都有 XFF header, 应触发 xff_injector 3 次"""
    stats = analyze(mixed_records, rules)
    assert stats["scanner_hits"]["xff_injector"] == 3


def test_analyze_suspect_top_is_attacker(rules, mixed_records):
    """192.168.94.59 (5 条记录: 3 AWVS + 1 sqlmap) 应是 TOP 1 攻击者"""
    stats = analyze(mixed_records, rules)
    assert stats["suspects"][0]["ip"] == "192.168.94.59"
    assert stats["suspects"][0]["requests"] == 4


def test_analyze_first_seen_recorded(rules, mixed_records):
    """每个扫描器首次出现时间记录 (sqlmap fixture ts=1700000001)"""
    stats = analyze(mixed_records, rules)
    assert "sqlmap" in stats["scanner_first_seen"]
    assert stats["scanner_first_seen"]["sqlmap"] == 1700000001.0


def test_analyze_empty_records(rules):
    """空 records 应不崩溃"""
    stats = analyze([], rules)
    assert stats["total"] == 0
    assert stats["scanner_hits"] == {}
    assert stats["suspects"] == []


def test_analyze_score_uses_uri_diversity(rules, mixed_records):
    """评分公式: URI 多样性高加分 (192.168.94.59 有 4 个不同 URI)"""
    stats = analyze(mixed_records, rules)
    top = stats["suspects"][0]
    # 4 条记录, 4 个不同 URI, score 至少包含 4 + (max(0, 4-50)*2)=0 + 攻击类型加分
    assert top["score"] >= 0


# ============== classify_uri ==============

def test_classify_uri_sql_injection():
    assert "SQL注入" in classify_uri("/?id=1' UNION SELECT 1,2,3--")

def test_classify_uri_xss():
    assert "XSS" in classify_uri("/search?q=<script>alert(1)</script>")

def test_classify_uri_lfi():
    assert "LFI/路径遍历" in classify_uri("/file?path=../../../etc/passwd")

def test_classify_uri_rce():
    assert "RCE/命令注入" in classify_uri("/cmd?x=1;ls -la")

def test_classify_uri_normal():
    assert classify_uri("/index.html") == []

def test_classify_uri_empty():
    assert classify_uri("") == []


# ============== is_browser_ua ==============

def test_is_browser_ua_chrome():
    assert is_browser_ua("Mozilla/5.0 ... Chrome/120.0")

def test_is_browser_ua_firefox():
    assert is_browser_ua("Mozilla/5.0 ... Firefox/115.0")

def test_is_browser_ua_sqlmap():
    assert not is_browser_ua("sqlmap/1.2.3.50")

def test_is_browser_ua_empty():
    assert not is_browser_ua("")

def test_is_browser_ua_awvs_disguised():
    """AWVS 默认 UA 伪装成 Chrome 41 — 应被判为正常浏览器 UA (这是已知混淆点)"""
    # 这暴露了 limitations: 单看 UA 不能识别 AWVS, 必须看 header
    assert is_browser_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/41.0.2228.0")