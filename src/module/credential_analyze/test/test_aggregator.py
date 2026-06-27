"""test_aggregator.py - 聚合分析单测"""
from src.module.credential_analyze.script import (
    aggregate_by_credential,
    build_attacker_profiles,
    collect_credential_attempts,
)


# ============== collect_credential_attempts ==============

def test_collect_filters_404(attack_http_data, paths_data):
    """404 响应被过滤掉"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    for a in attempts:
        assert a["status"] in (200, 302)


def test_collect_filters_get(attack_http_data, paths_data):
    """GET 请求被过滤掉 (s10 是 GET)"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    for a in attempts:
        assert a["method"] == "POST"


def test_collect_filters_multipart(attack_http_data, paths_data):
    """multipart body 被过滤掉 (s11)"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    # s11 IP 是 192.168.94.59, admin 路径, 但 multipart 被过滤
    # 检查没有 multipart 留下的痕迹 — 简单做法: 看是否有 '其他字段'
    ips_with_creds = {(a["ip_src"], a["username"]) for a in attempts}
    # 应该没有 (192.168.94.59, "") 这种空 username
    assert (None, "") not in ips_with_creds
    for a in attempts:
        assert a["username"] or a["password"]  # 至少一个


def test_collect_filters_empty_body(attack_http_data, paths_data):
    """空 body 被过滤掉 (s12)"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    # s12 没凭证 → 不应出现
    for a in attempts:
        assert a["form_keys"]  # 非空


def test_collect_returns_sorted_by_ts(attack_http_data, paths_data):
    """attempts 按时间升序"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    ts_list = [a["ts_epoch"] for a in attempts]
    assert ts_list == sorted(ts_list)


def test_collect_includes_302(attack_http_data, paths_data):
    """302 真登录成功的请求保留"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    statuses = [a["status"] for a in attempts]
    assert 302 in statuses


def test_collect_includes_legit_user(attack_http_data, paths_data):
    """正常用户 (s9 192.168.32.100) 也会出现在 attempts — 这是合法登录"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    ips = {a["ip_src"] for a in attempts}
    assert "192.168.32.100" in ips


def test_collect_total_count(attack_http_data, paths_data):
    """fixture 总数: 12 条 rec, 4 条被过滤 (s5=404, s10=GET, s11=multipart, s12=空body) → 8 条"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    assert len(attempts) == 8


# ============== aggregate_by_credential ==============

def test_aggregate_by_credential_count(attack_http_data, paths_data):
    """按 (path, user, pass) 聚合 — 每组 1 次 (fixture 里没重复)"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    by_cred = aggregate_by_credential(attempts)
    # fixture 8 条尝试, 每条凭证唯一 → 8 组
    assert len(by_cred) == 8
    for row in by_cred:
        assert row["count"] == 1


def test_aggregate_by_credential_top_sort(attack_http_data, paths_data):
    """默认按 count 降序"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    by_cred = aggregate_by_credential(attempts)
    counts = [r["count"] for r in by_cred]
    assert counts == sorted(counts, reverse=True)


def test_aggregate_by_credential_ips(attack_http_data, paths_data):
    """每组的 ips 字段正确"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    by_cred = aggregate_by_credential(attempts)
    # admin/admin123 → 1 次 (s1)
    admin_admin123 = next(r for r in by_cred
                          if r["username"] == "admin" and r["password"] == "admin123")
    assert admin_admin123["ips"] == ["192.168.94.59"]
    assert admin_admin123["sample_status"] == 200


def test_aggregate_repeats():
    """同一组凭证重复用, count 应累加"""
    from src.module.credential_analyze.script import collect_credential_attempts, aggregate_by_credential
    # 构造一个攻击者 admin/admin123 重复 5 次
    attempts = []
    for i in range(5):
        attempts.append({
            "path_id": "p1", "path_name": "Login",
            "path_category": "login",
            "uri": "/admin/login.php", "host": "t.com",
            "ts_epoch": 1700000000 + i * 60,
            "ip_src": "1.2.3.4", "ua": "",
            "username": "admin", "password": "admin123",
            "form_keys": ["username", "password"],
            "status": 302, "ts_str": "",
        })
    by_cred = aggregate_by_credential(attempts)
    assert len(by_cred) == 1
    assert by_cred[0]["count"] == 5


# ============== build_attacker_profiles ==============

def test_attacker_profiles_ips(attack_http_data, paths_data):
    """3 个攻击者 IP: 192.168.94.59 (主), 192.168.94.233 (伴), 192.168.32.100 (正常)"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    profiles = build_attacker_profiles(attempts)
    ips = [p["ip"] for p in profiles]
    assert "192.168.94.59" in ips
    assert "192.168.94.233" in ips
    assert "192.168.32.100" in ips


def test_attacker_profiles_attempts(attack_http_data, paths_data):
    """192.168.94.59 主攻有 7 条尝试 (s1-s5, s6, s7; s11/s12 不计)"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    profiles = build_attacker_profiles(attempts)
    main = next(p for p in profiles if p["ip"] == "192.168.94.59")
    # s1-s7 中 s5 是 404 被过滤 → 6 条
    # s6 s7 是 wp-login
    assert main["attempts"] == 6


def test_attacker_profiles_username_set(attack_http_data, paths_data):
    """主攻用了 admin 和 root 两个用户名"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    profiles = build_attacker_profiles(attempts)
    main = next(p for p in profiles if p["ip"] == "192.168.94.59")
    assert "admin" in main["username_set"]
    assert "root" in main["username_set"]


def test_attacker_profiles_unique_creds(attack_http_data, paths_data):
    """主攻用了 6 组独立凭证"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    profiles = build_attacker_profiles(attempts)
    main = next(p for p in profiles if p["ip"] == "192.168.94.59")
    # s1 admin/admin123, s2 admin/qwerty, s3 admin/123456, s4 root/toor,
    # s6 admin/password(wp), s7 admin/admin(wp) — 但 wp-login 路径不同 (path_id 不同)
    # 所以 unique_credentials 应该是 6 (4 个 /admin + 2 个 /wp)
    assert main["unique_credentials"] == 6


def test_attacker_profiles_top_sort(attack_http_data, paths_data):
    """profiles 按 attempts 降序"""
    attempts = collect_credential_attempts(attack_http_data, paths_data)
    profiles = build_attacker_profiles(attempts)
    counts = [p["attempts"] for p in profiles]
    assert counts == sorted(counts, reverse=True)


def test_attacker_profiles_min_attempts_filter():
    """min_attempts 过滤 — 攻击者 1 次尝试被过滤"""
    attempts = [
        {
            "path_id": "p1", "path_name": "L", "path_category": "login",
            "uri": "/admin/login.php", "host": "t.com",
            "ts_epoch": 1700000000,
            "ip_src": "1.2.3.4", "ua": "",
            "username": "admin", "password": "test",
            "form_keys": [], "status": 200, "ts_str": "",
        },
        {
            "path_id": "p1", "path_name": "L", "path_category": "login",
            "uri": "/admin/login.php", "host": "t.com",
            "ts_epoch": 1700000060,
            "ip_src": "5.6.7.8", "ua": "",
            "username": "user", "password": "pass",
            "form_keys": [], "status": 200, "ts_str": "",
        },
        {
            "path_id": "p1", "path_name": "L", "path_category": "login",
            "uri": "/admin/login.php", "host": "t.com",
            "ts_epoch": 1700000120,
            "ip_src": "5.6.7.8", "ua": "",
            "username": "user", "password": "pass",
            "form_keys": [], "status": 200, "ts_str": "",
        },
    ]
    profiles_1 = build_attacker_profiles(attempts, min_attempts=1)
    profiles_2 = build_attacker_profiles(attempts, min_attempts=2)
    assert len(profiles_1) == 2
    assert len(profiles_2) == 1
    assert profiles_2[0]["ip"] == "5.6.7.8"