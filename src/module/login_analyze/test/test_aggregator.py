"""test_aggregator.py - 测聚合逻辑 (path × IP × 时间)"""
import pytest

from src.module.login_analyze.script import (
    aggregate_login_paths,
    build_attacker_profiles,
)


# ============== aggregate_login_paths ==============

def test_aggregate_orders_by_hits(paths_data, attack_records):
    """按 hits 降序排序"""
    summary = aggregate_login_paths(attack_records, paths_data)
    assert len(summary) >= 4
    # yaml 顺序决定优先级 — 一条 /admin/login 只触发 admin_generic (yaml 排第一)
    #   admin_generic: 50 次 (50 /admin/login?id=N)
    #   phpmyadmin: 30 次
    #   wordpress: 20 次
    #   tomcat: 10 次
    assert summary[0]["path_id"] == "admin_generic"
    assert summary[0]["hits"] == 50
    hits_list = [r["hits"] for r in summary]
    assert hits_list == sorted(hits_list, reverse=True)


def test_aggregate_ip_count(paths_data, attack_records):
    """IP 数统计正确"""
    summary = aggregate_login_paths(attack_records, paths_data)
    admin_row = next(r for r in summary if r["path_id"] == "admin_generic")
    # 192.168.94.59 访问了 50 次, 192.168.32.100 没访问 admin
    assert "192.168.94.59" in admin_row["ips"]
    assert admin_row["ip_count"] == 1
    # login_generic: 192.168.32.100 的 /login 不再被 admin_generic 抢 (因为 /admin/login 排前)
    # 所以 login_generic 计数 = 1 (只有那 1 次 /login)
    login_row = next(r for r in summary if r["path_id"] == "login_generic")
    assert login_row["hits"] == 1
    assert "192.168.32.100" in login_row["ips"]


def test_aggregate_time_range(paths_data, attack_records):
    """时间范围记录"""
    summary = aggregate_login_paths(attack_records, paths_data)
    admin_row = next(r for r in summary if r["path_id"] == "admin_generic")
    assert admin_row["first_seen"] == 1700000000.0
    assert admin_row["last_seen"] == 1700000000 + 49 * 60  # 49 次 60s 间隔


def test_aggregate_empty_records(paths_data):
    """空 records 不应崩溃"""
    summary = aggregate_login_paths([], paths_data)
    assert summary == []


def test_aggregate_records_with_no_hits(paths_data, make_record):
    """所有记录都不命中 (普通页面)"""
    records = [
        make_record(0, "1.2.3.4", "GET", "x.com", "/index.html"),
        make_record(0, "1.2.3.4", "GET", "x.com", "/about"),
        make_record(0, "1.2.3.4", "GET", "x.com", "/api/products"),
    ]
    summary = aggregate_login_paths(records, paths_data)
    assert summary == []


# ============== build_attacker_profiles ==============

def test_attacker_profile_min_hits_filter(paths_data, attack_records):
    """min_hits 过滤低频 IP"""
    profiles = build_attacker_profiles(attack_records, paths_data, min_hits=5)
    ips = [p["ip"] for p in profiles]
    # 192.168.94.59: 100 次 (50+20+30)
    # 10.0.0.5: 10 次
    # 192.168.32.100: 1 次 (login_generic), 被过滤
    assert "192.168.94.59" in ips
    assert "10.0.0.5" in ips
    assert "192.168.32.100" not in ips


def test_attacker_profile_orders_by_total_hits(paths_data, attack_records):
    """profile 按 total_hits 降序"""
    profiles = build_attacker_profiles(attack_records, paths_data, min_hits=5)
    totals = [p["total_hits"] for p in profiles]
    assert totals == sorted(totals, reverse=True)
    assert profiles[0]["ip"] == "192.168.94.59"


def test_attacker_profile_paths_listed(paths_data, attack_records):
    """profile 列出访问过的后台"""
    profiles = build_attacker_profiles(attack_records, paths_data, min_hits=5)
    main = next(p for p in profiles if p["ip"] == "192.168.94.59")
    path_ids = [p["path_id"] for p in main["paths"]]
    assert "admin_generic" in path_ids
    assert "wordpress" in path_ids
    assert "phpmyadmin" in path_ids


def test_attacker_profile_paths_ordered_by_hits(paths_data, attack_records):
    """profile.paths 按 hits 降序"""
    profiles = build_attacker_profiles(attack_records, paths_data, min_hits=5)
    main = next(p for p in profiles if p["ip"] == "192.168.94.59")
    path_hits = [p["hits"] for p in main["paths"]]
    assert path_hits == sorted(path_hits, reverse=True)