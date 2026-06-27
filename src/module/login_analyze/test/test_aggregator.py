"""test_aggregator.py - 测聚合 (含方法过滤 + 状态过滤)"""
import pytest

from src.module.login_analyze.script import (
    aggregate_login_paths,
    build_attacker_profiles,
)


# ============== aggregate_login_paths ==============

def test_aggregate_orders_by_hits(paths_data, attack_http_data):
    """按 hits 降序排序, 404 + GET-only (非 POST-only rule) 被过滤"""
    summary = aggregate_login_paths(attack_http_data, paths_data)
    # attack_http_data 里 POST 命中统计 (longest-match-first):
    #   login_generic: 50 (POST /admin/login) + 1 (POST /login from 192.168.32.100) + 10 (POST /user/login from 10.0.0.5) = 61
    #   phpmyadmin:    30 (POST /phpmyadmin/index.php)
    #   wordpress:     30 (20 POST + 10 GET, wp 允许 [GET, POST])
    ids = [r["path_id"] for r in summary]
    assert "login_generic" in ids
    assert "wordpress" in ids
    assert "phpmyadmin" in ids
    # 404 探测 + GET /login (login_generic POST-only) 应被过滤
    assert sum(r["hits"] for r in summary) == 61 + 30 + 30
    hits_list = [r["hits"] for r in summary]
    assert hits_list == sorted(hits_list, reverse=True)


def test_aggregate_filters_404(paths_data, make_record):
    """4xx/5xx 响应被过滤, 不计入聚合"""
    requests = []
    responses = {}

    # 5 次 404 (探测失败)
    for i in range(5):
        sid = f"s_{i}"
        requests.append(make_record(
            100, "1.2.3.4", "POST", "x.com", "/admin/login", stream_id=sid,
        ))
        responses[sid] = 404

    # 3 次 200 (真存在)
    for i in range(3):
        sid = f"s_ok_{i}"
        requests.append(make_record(
            100, "1.2.3.4", "POST", "x.com", "/admin/login", stream_id=sid,
        ))
        responses[sid] = 200

    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    admin_row = next(r for r in summary if r["path_id"] == "login_generic")
    assert admin_row["hits"] == 3, "404 应被过滤, 只计 200"
    assert admin_row["status_codes"] == {200: 3}


def test_aggregate_filters_wrong_method(paths_data, make_record):
    """GET 请求命中 POST-only rule 被过滤 (POST 是登录提交凭证的金标准)"""
    requests = []
    responses = {}

    # 5 次 GET /admin/login (rule.methods=[POST], 应全过滤)
    for i in range(5):
        sid = f"s_get_{i}"
        requests.append(make_record(
            100, "1.2.3.4", "GET", "x.com", "/admin/login", stream_id=sid,
        ))
        responses[sid] = 200

    # 3 次 POST /admin/login (应计)
    for i in range(3):
        sid = f"s_post_{i}"
        requests.append(make_record(
            100, "1.2.3.4", "POST", "x.com", "/admin/login", stream_id=sid,
        ))
        responses[sid] = 200

    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    admin_row = next(r for r in summary if r["path_id"] == "login_generic")
    assert admin_row["hits"] == 3, "GET 应被 POST-only 规则过滤"


def test_aggregate_allows_get_post_for_wordpress(paths_data, make_record):
    """WordPress 规则 methods=[GET, POST], 两种都算登录尝试"""
    requests = [
        make_record(100, "1.2.3.4", "GET", "x.com", "/wp-login.php", stream_id="g"),
        make_record(200, "1.2.3.4", "POST", "x.com", "/wp-login.php", stream_id="p"),
    ]
    responses = {"g": 200, "p": 200}

    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    wp_row = next(r for r in summary if r["path_id"] == "wordpress")
    assert wp_row["hits"] == 2


def test_aggregate_includes_302(paths_data, make_record):
    """302 (登录成功重定向到 dashboard) 也算'找到了'"""
    requests = [
        make_record(100, "1.2.3.4", "POST", "x.com", "/admin/login?rec=login",
                    stream_id="s1"),
    ]
    responses = {"s1": 302}

    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    assert len(summary) == 1
    assert summary[0]["hits"] == 1
    assert summary[0]["status_codes"] == {302: 1}


def test_aggregate_ip_count(paths_data, attack_http_data):
    """IP 数统计 (跨 IP 命中)"""
    summary = aggregate_login_paths(attack_http_data, paths_data)
    # login_generic 跨 3 个 IP: 192.168.94.59 (50 admin/login) + 192.168.32.100 (1 /login) + 10.0.0.5 (10 /user/login)
    admin_row = next(r for r in summary if r["path_id"] == "login_generic")
    assert admin_row["ip_count"] == 3
    assert "192.168.94.59" in admin_row["ips"]
    assert "192.168.32.100" in admin_row["ips"]
    assert "10.0.0.5" in admin_row["ips"]


def test_aggregate_sample_uri_preserves_query(paths_data, make_record):
    """sample_uri 保留完整 URI (含 query string)"""
    requests = [
        make_record(100, "1.2.3.4", "POST", "x.com",
                    "/admin/login?rec=manager_log", stream_id="s1"),
    ]
    responses = {"s1": 200}

    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    admin_row = next(r for r in summary if r["path_id"] == "login_generic")
    assert admin_row["sample_uri"] == "/admin/login?rec=manager_log"


def test_aggregate_methods_field(paths_data, make_record):
    """汇总行带 methods 字段 (报告输出用)"""
    requests = [
        make_record(100, "1.2.3.4", "POST", "x.com", "/admin/login", stream_id="s1"),
    ]
    responses = {"s1": 200}

    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    admin_row = next(r for r in summary if r["path_id"] == "login_generic")
    assert admin_row["methods"] == ["POST"]


def test_aggregate_time_range(paths_data, attack_http_data):
    """时间范围记录 (login_generic 在 fixture 中最后被访问是 10.0.0.5 的 /user/login)"""
    summary = aggregate_login_paths(attack_http_data, paths_data)
    admin_row = next(r for r in summary if r["path_id"] == "login_generic")
    # login_generic 跨 3 IP 跨整个 fixture 时间, last_seen = 1700005000 + 9*60 = 1700005540
    assert admin_row["first_seen"] == 1700000000.0
    assert admin_row["last_seen"] == 1700005000 + 9 * 60


def test_aggregate_empty_records(paths_data):
    """空 records"""
    summary = aggregate_login_paths(
        {"requests": [], "responses_by_stream": {}},
        paths_data,
    )
    assert summary == []


def test_aggregate_records_with_no_hits(paths_data, make_record):
    """所有记录都不命中任何 rule (非登录 URI)"""
    requests = [
        make_record(0, "1.2.3.4", "POST", "x.com", "/index.html", stream_id="s"),
    ]
    responses = {"s": 200}
    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    assert summary == []


# ============== build_attacker_profiles ==============

def test_attacker_profile_min_hits_filter(paths_data, attack_http_data):
    """min_hits 过滤低频 IP"""
    profiles = build_attacker_profiles(attack_http_data, paths_data, min_hits=3)
    ips = [p["ip"] for p in profiles]
    # 192.168.94.59: 50 (admin POST) + 30 (wp 20POST+10GET) + 30 (pma) = 110
    # 10.0.0.5: 10 (login_generic via /user/login, longest-match)
    # 192.168.32.100: 1 (login POST), 被 min_hits=3 过滤
    assert "192.168.94.59" in ips
    assert "10.0.0.5" in ips
    assert "192.168.32.100" not in ips


def test_attacker_profile_orders_by_total_hits(paths_data, attack_http_data):
    """profile 按 total_hits 降序"""
    profiles = build_attacker_profiles(attack_http_data, paths_data, min_hits=3)
    totals = [p["total_hits"] for p in profiles]
    assert totals == sorted(totals, reverse=True)
    assert profiles[0]["ip"] == "192.168.94.59"


def test_attacker_profile_paths_listed(paths_data, attack_http_data):
    """profile 列出访问过的后台"""
    profiles = build_attacker_profiles(attack_http_data, paths_data, min_hits=3)
    main = next(p for p in profiles if p["ip"] == "192.168.94.59")
    path_ids = [p["path_id"] for p in main["paths"]]
    assert "login_generic" in path_ids
    assert "wordpress" in path_ids
    assert "phpmyadmin" in path_ids
    # 攻击者 20 次 GET /login 被 login_generic (POST-only) 过滤, 不计入 IP 总数


def test_attacker_profile_sample_uri(paths_data, make_record):
    """profile 中 path 含 sample_uri (完整 URL)"""
    requests = [
        make_record(100, "1.2.3.4", "POST", "x.com",
                    "/admin/login?rec=manager_log", stream_id="s"),
    ]
    responses = {"s": 200}

    profiles = build_attacker_profiles(
        {"requests": requests, "responses_by_stream": responses},
        paths_data, min_hits=1,
    )
    main = profiles[0]
    admin_path = main["paths"][0]
    assert admin_path["sample_uri"] == "/admin/login?rec=manager_log"


def test_attacker_profile_excludes_404_attempts(paths_data, make_record):
    """攻击者大量 404 探测不计入画像"""
    attacker = "1.2.3.4"
    requests = []
    responses = {}
    # 100 次 404 探测 /admin/login
    for i in range(100):
        sid = f"s_{i}"
        requests.append(make_record(100, attacker, "POST", "x.com",
                                    "/admin/login", stream_id=sid))
        responses[sid] = 404
    # 1 次 200 命中 /admin/login (真找到)
    requests.append(make_record(200, attacker, "POST", "x.com",
                                "/admin/login", stream_id="s_ok"))
    responses["s_ok"] = 200

    profiles = build_attacker_profiles(
        {"requests": requests, "responses_by_stream": responses},
        paths_data, min_hits=1,
    )
    assert profiles[0]["total_hits"] == 1
    assert profiles[0]["paths"][0]["hits"] == 1


def test_attacker_profile_excludes_wrong_method_attempts(paths_data, make_record):
    """攻击者大量 GET /admin/login 不计入画像 (POST-only rule)"""
    attacker = "1.2.3.4"
    requests = []
    responses = {}
    # 100 次 GET /admin/login (rule.methods=[POST], 应全过滤)
    for i in range(100):
        sid = f"s_{i}"
        requests.append(make_record(100, attacker, "GET", "x.com",
                                    "/admin/login", stream_id=sid))
        responses[sid] = 200
    # 1 次 POST /admin/login (应计)
    requests.append(make_record(200, attacker, "POST", "x.com",
                                "/admin/login", stream_id="s_ok"))
    responses["s_ok"] = 200

    profiles = build_attacker_profiles(
        {"requests": requests, "responses_by_stream": responses},
        paths_data, min_hits=1,
    )
    assert profiles[0]["total_hits"] == 1
    assert profiles[0]["paths"][0]["hits"] == 1
