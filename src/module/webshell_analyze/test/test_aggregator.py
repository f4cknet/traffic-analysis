"""test_aggregator.py - 聚合单测"""
from src.module.webshell_analyze.script import (
    build_attacker_profiles,
    collect_accesses,
    collect_uploads,
    find_orphan_accesses,
    link_uploads_to_accesses,
)


# ============== collect_uploads ==============

def test_collect_uploads_count(attack_http_data):
    """fixture 1 条 multipart 上传"""
    uploads = collect_uploads(attack_http_data)
    assert len(uploads) == 1


def test_collect_uploads_filename(attack_http_data):
    uploads = collect_uploads(attack_http_data)
    assert uploads[0]["filename"] == "hello.html"


def test_collect_uploads_sorted_by_ts(attack_http_data):
    """按 ts_epoch 升序"""
    uploads = collect_uploads(attack_http_data)
    assert len(uploads) == 1
    # 单条, 不需要排序, 但应该有时间戳
    assert uploads[0]["ts_epoch"] == 1700000000


def test_collect_uploads_ip(attack_http_data):
    """上传 IP"""
    uploads = collect_uploads(attack_http_data)
    assert uploads[0]["ip_src"] == "192.168.94.59"


# ============== collect_accesses ==============

def test_collect_accesses_count(attack_http_data, paths_data, field_aliases):
    """fixture 期望 5 条访问:
    - 3 条 hello.html (URL 命中 /upload/ + body pass/cmd)
    - 1 条 /shell.php (URL 命中 generic_php + body pass/cmd)
    - /upload/image.jpg (命中 upload_dir 但 pass/cmd 都空, 应该不算 — 没 password 字段)
    - /index.html (不命中)

    实际期望: 4 条 (image.jpg 因 upload_dir 命中但无 password, 仍算 path_match)
    """
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    # upload_dir 命中 + 无 password → path_match 仍算
    assert len(accesses) == 5  # 3 hello.html + 1 /shell.php + 1 /upload/image.jpg


def test_collect_accesses_hello_html(attack_http_data, paths_data, field_aliases):
    """hello.html 访问: path 命中 upload_dir + password 命中"""
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    hello = [a for a in accesses if "hello.html" in a["uri"]]
    assert len(hello) == 3
    for h in hello:
        assert h["path_id"] == "upload_dir"
        assert h["password"] == "cmdtest"


def test_collect_accesses_cmd_extracted(attack_http_data, paths_data, field_aliases):
    """cmd 参数被提取"""
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    hello = [a for a in accesses if "hello.html" in a["uri"]]
    cmds = {a["cmd"] for a in hello}
    assert "whoami" in cmds
    assert "id" in cmds


def test_collect_accesses_shell_php(attack_http_data, paths_data, field_aliases):
    """/shell.php 命中 generic_php"""
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    shell = [a for a in accesses if "shell.php" in a["uri"]]
    assert len(shell) == 1
    assert shell[0]["path_id"] == "generic_php"


def test_collect_accesses_index_not_matched(attack_http_data, paths_data, field_aliases):
    """/index.html 不命中 (既不路径也不含密码字段)"""
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    assert not any("index.html" in a["uri"] for a in accesses)


# ============== link_uploads_to_accesses ==============

def test_link_count(attack_http_data, paths_data, field_aliases):
    """1 个上传文件 → 1 条 link"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    assert len(linked) == 1


def test_link_filename(attack_http_data, paths_data, field_aliases):
    """filename 正确"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    assert linked[0]["filename"] == "hello.html"


def test_link_access_count(attack_http_data, paths_data, field_aliases):
    """hello.html 后续 3 条访问"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    assert linked[0]["access_count"] == 3


def test_link_passwords(attack_http_data, paths_data, field_aliases):
    """提取的密码集合"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    assert "cmdtest" in linked[0]["passwords_seen"]


def test_link_cmds(attack_http_data, paths_data, field_aliases):
    """提取的命令集合"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    cmds = linked[0]["cmds_seen"]
    assert "whoami" in cmds
    assert "id" in cmds
    assert "cat /etc/passwd" in cmds


def test_link_first_last_access_ts(attack_http_data, paths_data, field_aliases):
    """首访/末访时间戳"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    assert linked[0]["first_access_ts"] == 1700000060
    assert linked[0]["last_access_ts"] == 1700000180


# ============== find_orphan_accesses ==============

def test_orphan_count(attack_http_data, paths_data, field_aliases):
    """/shell.php 没匹配上传 → orphan"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    orphans = find_orphan_accesses(uploads, accesses)
    # hello.html 3 条被 upload 关联, /shell.php 是 orphan
    # /upload/image.jpg: 文件名含 "/upload/" + "image.jpg" — 不包含 "hello.html", 算 orphan
    # 期望 orphan: /shell.php + /upload/image.jpg = 2 条
    assert len(orphans) == 2


def test_orphan_shell_php(attack_http_data, paths_data, field_aliases):
    """orphan 里应该有 /shell.php"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    orphans = find_orphan_accesses(uploads, accesses)
    assert any("shell.php" in o["uri"] for o in orphans)


# ============== build_attacker_profiles ==============

def test_attacker_profiles_count(attack_http_data, paths_data, field_aliases):
    """1 个攻击者 IP"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    orphans = find_orphan_accesses(uploads, accesses)
    profiles = build_attacker_profiles(linked, orphans)
    assert len(profiles) == 1


def test_attacker_profiles_actions(attack_http_data, paths_data, field_aliases):
    """上传 1 次 + 访问 5 次 (3 linked hello + 1 orphan shell.php + 1 orphan image.jpg)"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    orphans = find_orphan_accesses(uploads, accesses)
    profiles = build_attacker_profiles(linked, orphans)
    p = profiles[0]
    assert p["ip"] == "192.168.94.59"
    assert p["upload_count"] == 1
    assert p["access_count"] == 5  # 3 hello + 2 orphan
    assert p["total_actions"] == 6


def test_attacker_profiles_time_range(attack_http_data, paths_data, field_aliases):
    """first/last_seen 范围"""
    uploads = collect_uploads(attack_http_data)
    accesses = collect_accesses(attack_http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    orphans = find_orphan_accesses(uploads, accesses)
    profiles = build_attacker_profiles(linked, orphans)
    p = profiles[0]
    assert p["first_seen"] == 1700000000
    assert p["last_seen"] == 1700000400  # image.jpg 是最晚的