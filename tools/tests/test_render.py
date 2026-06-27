"""test_render.py - 测 Markdown 报告渲染"""
import re
from pathlib import Path

import pytest

from analyzer_core import render_md


@pytest.fixture
def report_path(tmp_path):
    return tmp_path / "report.md"


def test_render_md_creates_file(rules, mixed_records, report_path):
    """应创建 Markdown 文件"""
    from analyzer_core import analyze
    stats = analyze(mixed_records, rules)
    pcap_path = Path("test.pcap")
    out = render_md(stats, rules, pcap_path, report_path)
    assert report_path.exists()
    assert isinstance(out, str)
    assert len(out) > 100


def test_render_md_has_required_sections(rules, mixed_records, report_path):
    """6 个章节标题应齐全"""
    from analyzer_core import analyze
    stats = analyze(mixed_records, rules)
    pcap_path = Path("test.pcap")
    text = render_md(stats, rules, pcap_path, report_path)

    for section in (
        "## 一、扫描器识别结果",
        "## 二、判定强度说明",
        "## 三、疑似攻击者 IP 排行",
        "## 四、各 IP 上的扫描器命中详情",
        "## 五、典型 Payload 样例",
        "## 六、关键结论",
    ):
        assert section in text, f"缺章节: {section}"


def test_render_md_lists_awvs(rules, mixed_records, report_path):
    """AWVS 命中应在 '一、扫描器识别结果' 表里出现"""
    from analyzer_core import analyze
    stats = analyze(mixed_records, rules)
    text = render_md(stats, rules, Path("test.pcap"), report_path)
    assert "Acunetix" in text, "AWVS 名字应在报告中"


def test_render_md_top_attacker_visible(rules, mixed_records, report_path):
    """TOP 攻击者 IP 应在报告中"""
    from analyzer_core import analyze
    stats = analyze(mixed_records, rules)
    text = render_md(stats, rules, Path("test.pcap"), report_path)
    assert "192.168.94.59" in text


def test_render_md_creates_parent_dir(rules, mixed_records, tmp_path):
    """out_path 的父目录不存在时应自动创建"""
    from analyzer_core import analyze
    stats = analyze(mixed_records, rules)
    nested = tmp_path / "deep" / "nested" / "report.md"
    assert not nested.parent.exists()
    render_md(stats, rules, Path("test.pcap"), nested)
    assert nested.exists()


def test_render_md_includes_pcap_name(rules, mixed_records, report_path):
    """报告应包含 pcap 文件名"""
    from analyzer_core import analyze
    stats = analyze(mixed_records, rules)
    text = render_md(stats, rules, Path("specific_test.pcap"), report_path)
    assert "specific_test.pcap" in text


def test_render_md_strong_label(rules, mixed_records, report_path):
    """强证据应标 '**强**' (AWVS 是 header 强命中)"""
    from analyzer_core import analyze
    stats = analyze(mixed_records, rules)
    text = render_md(stats, rules, Path("test.pcap"), report_path)
    # 一、扫描器识别结果 章节应含 '**强**' 标识 (AWVS header 命中)
    sec1 = text.split("## 二、")[0]
    assert "**强**" in sec1, "AWVS 应标 '**强**'"


def test_render_md_well_formed_table(rules, mixed_records, report_path):
    """表格行格式正确 (| 分隔, 不是空表)"""
    from analyzer_core import analyze
    stats = analyze(mixed_records, rules)
    text = render_md(stats, rules, Path("test.pcap"), report_path)
    # 检查至少有一个表头分隔行 (|---|)
    table_seps = re.findall(r"^\|[-:|\s]+\|$", text, re.M)
    assert len(table_seps) >= 3, f"Markdown 表格分隔行不足: {len(table_seps)}"