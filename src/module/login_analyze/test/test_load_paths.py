"""test_load_paths.py - 测 login_paths.yaml 加载与结构"""
import pytest


def test_load_rules_returns_dict(paths_data):
    assert isinstance(paths_data, dict)
    assert "login_paths" in paths_data
    assert "path_by_id" in paths_data
    assert isinstance(paths_data["login_paths"], list)
    assert isinstance(paths_data["path_by_id"], dict)


def test_load_rules_compiles_patterns_lower(paths_data):
    """patterns 预编译为小写, 匹配时大小写不敏感"""
    for lp in paths_data["login_paths"]:
        assert "_patterns_lower" in lp
        assert all(p == p.lower() for p in lp["_patterns_lower"])


def test_load_rules_min_count(paths_data):
    """至少 20 条规则 (覆盖 admin/CMS/db/framework/app)"""
    assert len(paths_data["login_paths"]) >= 20


def test_core_login_paths_present(paths_data):
    """关键后台规则必须在"""
    ids = {lp["id"] for lp in paths_data["login_paths"]}
    for required in ("admin_generic", "wordpress", "phpmyadmin", "tomcat"):
        assert required in ids, f"缺关键后台: {required}"


def test_no_duplicate_ids(paths_data):
    """id 唯一"""
    ids = [lp["id"] for lp in paths_data["login_paths"]]
    assert len(ids) == len(set(ids))


def test_each_path_has_required_fields(paths_data):
    """每条规则 id/name/patterns 字段齐全"""
    for lp in paths_data["login_paths"]:
        missing = {"id", "name", "patterns"} - set(lp.keys())
        assert not missing, f"{lp.get('id', '?')} 缺字段: {missing}"
        assert len(lp["patterns"]) > 0, f"{lp['id']} patterns 不能为空"


def test_patterns_are_strings(paths_data):
    """patterns 应是字符串列表"""
    for lp in paths_data["login_paths"]:
        for p in lp["patterns"]:
            assert isinstance(p, str), f"{lp['id']} pattern 非字符串: {p}"
            assert p.startswith("/"), f"{lp['id']} pattern 应以 / 开头: {p}"