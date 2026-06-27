"""test_aggregator.py - 测聚合 (含响应状态过滤)"""
import pytest

from src.module.login_analyze.script import (
    aggregate_login_paths,
    build_attacker_profiles,
)


# ============== aggregate_login_paths ==============

def test_aggregate_orders_by_hits(paths_data, attack_http_data):
    """按 hits 降序排序, 404 探测被过滤"""
    summary = aggregate_login_paths(attack_http_data, paths_data)
    # 排除 404 的 /admin/nonexistent (admin_generic 匹配 /admin 但 404 不过滤)
    #   admin_generic: 50 次 (50 /admin/login)
    #   phpmyadmin:    30 次
    #   wordpress:     20 次
    #   tomcat:        10 次
    assert len(summary) >= 4
    assert summary[0]["path_id"] == "admin_generic"
    assert summary[0]["hits"] == 50
    hits_list = [r["hits"] for r in summary]
    assert hits_list == sorted(hits_list, reverse=True)


def test_aggregate_filters_404(paths_data, make_record):
    """4xx/5xx 响应被过滤, 不计入聚合"""
    from src.module.login_analyze.script import aggregate_login_paths
    requests = []
    responses = {}

    # /admin/login 5 次全 404 (探测失败, 应全过滤)
    for i in range(5):
        sid = f"s_{i}"
        requests.append(make_record(
            100, "1.2.3.4", "GET", "x.com", "/admin/login", stream_id=sid,
        ))
        responses[sid] = 404

    # /admin/login 3 次 200 (真存在, 应计)
    for i in range(3):
        sid = f"s_ok_{i}"
        requests.append(make_record(
            100, "1.2.3.4", "GET", "x.com", "/admin/login", stream_id=sid,
        ))
        responses[sid] = 200

    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    admin_row = next(r for r in summary if r["path_id"] == "admin_generic")
    assert admin_row["hits"] == 3, "404 应被过滤, 只计 200"
    assert admin_row["status_codes"] == {200: 3}


def test_aggregate_includes_302(paths_data, make_record):
    """302 (重定向到登录页) 也算"找到了" """
    requests = [
        make_record(100, "1.2.3.4", "POST", "x.com", "/admin/login?rec=login",
                    stream_id="s1"),
    ]
    responses = {"s1": 302}  # 登录成功重定向到 dashboard

    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    assert len(summary) == 1
    assert summary[0]["hits"] == 1
    assert summary[0]["status_codes"] == {302: 1}


def test_aggregate_ip_count(paths_data, attack_http_data):
    """IP 数统计"""
    summary = aggregate_login_paths(attack_http_data, paths_data)
    admin_row = next(r for r in summary if r["path_id"] == "admin_generic")
    # 192.168.94.59 访问 50 次 (200), 192.168.32.100 访问 /login 不算 admin
    assert "192.168.94.59" in admin_row["ips"]
    assert admin_row["ip_count"] == 1


def test_aggregate_sample_uri_preserves_query(paths_data, make_record):
    """sample_uri 保留完整 URI (含 query string)"""
    requests = [
        make_record(100, "1.2.3.4", "GET", "x.com",
                    "/admin/manager.php?rec=manager_log", stream_id="s1"),
    ]
    responses = {"s1": 200}

    summary = aggregate_login_paths(
        {"requests": requests, "responses_by_stream": responses},
        paths_data,
    )
    admin_row = next(r for r in summary if r["path_id"] == "admin_generic")
    # 完整 URI 含 query 参数
    assert admin_row["sample_uri"] == "/admin/manager.php?rec=manager_log"


def test_aggregate_time_range(paths_data, attack_http_data):
    """时间范围记录"""
    summary = aggregate_login_paths(attack_http_data, paths_data)
    admin_row = next(r for r in summary if r["path_id"] == "admin_generic")
    assert admin_row["first_seen"] == 1700000000.0
    assert admin_row["last_seen"] == 1700000000 + 49 * 60


def test_aggregate_empty_records(paths_data):
    """空 records"""
    summary = aggregate_login_paths(
        {"requests": [], "responses_by_stream": {}},
        paths_data,
    )
    assert summary == []


def test_aggregate_records_with_no_hits(paths_data, make_record):
    """所有记录都不命中"""
    requests = [
        make_record(0, "1.2.3.4", "GET", "x.com", "/index.html", stream_id="s"),
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
    # 192.168.94.59: 100 次 (admin/login 50 + wp 20 + phpmyadmin 30)
    # 10.0.0.5: 10 次
    # 192.168.32.100: 1 次, 被过滤 (< 3)
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
    assert "admin_generic" in path_ids
    assert "wordpress" in path_ids
    assert "phpmyadmin" in path_ids


def test_attacker_profile_sample_uri(paths_data, make_record):
    """profile 中 path 含 sample_uri (完整 URL)"""
    requests = [
        make_record(100, "1.2.3.4", "GET", "x.com",
                    "/admin/manager.php?rec=manager_log", stream_id="s"),
    ]
    responses = {"s": 200}

    profiles = build_attacker_profiles(
        {"requests": requests, "responses_by_stream": responses},
        paths_data, min_hits=1,
    )
    main = profiles[0]
    admin_path = main["paths"][0]
    assert admin_path["sample_uri"] == "/admin/manager.php?rec=manager_log"


def test_attacker_profile_excludes_404_attempts(paths_data, make_record):
    """攻击者大量 404 探测不计入画像"""
    attacker = "1.2.3.4"
    requests = []
    responses = {}
    # 100 次 404 探测 /admin/login
    for i in range(100):
        sid = f"s_{i}"
        requests.append(make_record(100, attacker, "GET", "x.com",
                                    "/admin/login", stream_id=sid))
        responses[sid] = 404
    # 1 次 200 命中 /admin/login (真找到)
    requests.append(make_record(200, attacker, "GET", "x.com",
                                "/admin/login", stream_id="s_ok"))
    responses["s_ok"] = 200

    profiles = build_attacker_profiles(
        {"requests": requests, "responses_by_stream": responses},
        paths_data, min_hits=1,
    )
    # 100 次 404 全被过滤, 只算 1 次 200
    assert profiles[0]["total_hits"] == 1
    assert profiles[0]["paths"][0]["hits"] == 1