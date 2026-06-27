"""test_parser.py - webshell body 内容解析单测

主流 webshell 模式覆盖:
  - PHP eval/assert/system/exec + $_POST/$_GET/$_REQUEST
  - PHP call_user_func/array_map + $_POST
  - PHP base64_decode + $_POST (混淆)
  - PHP file_put_contents + $_POST
  - ASPX eval(Request["xxx"]) / eval(Request.Item["xxx"])
  - JSP request.getParameter("xxx")
"""
from src.module.webshell_analyze.script import (
    detect_webshell_functions,
    extract_webshell_from_multipart_body,
)


# ============== PHP 模式 ==============

def test_php_eval_post_string():
    """eval($_POST['pass'])"""
    body = b"<?php @eval($_POST['pass']);?>"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "eval" in r["functions"]
    assert "pass" in r["passwords"]
    assert r["language"] == "php"


def test_php_eval_post_double_quote():
    """eval($_POST["pass"])"""
    body = b'<?php eval($_POST["pass"]); ?>'
    r = detect_webshell_functions(body)
    assert r is not None
    assert "eval" in r["functions"]
    assert "pass" in r["passwords"]


def test_php_eval_post_no_quote():
    """eval($_POST[1234]) — 数字键无引号 (web_attack.pcap 真实场景)"""
    body = b"<?php @eval($_POST[1234]);?>"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "eval" in r["functions"]
    assert "1234" in r["passwords"]


def test_php_assert_post():
    """assert($_POST['x']) — 一句话常见模式"""
    body = b"<?php assert($_POST['x']);?>"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "assert" in r["functions"]
    assert "x" in r["passwords"]


def test_php_system_get():
    """system($_GET['cmd'])"""
    body = b"<?php system($_GET['cmd']);?>"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "system" in r["functions"]
    assert "cmd" in r["passwords"]


def test_php_request_super():
    """eval($_REQUEST['cmd']) — $_REQUEST 兼容 GET/POST"""
    body = b"<?php eval($_REQUEST['cmd']);?>"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "eval" in r["functions"]
    assert "cmd" in r["passwords"]


def test_php_call_user_func():
    """call_user_func + $_POST"""
    body = b"<?php call_user_func($_POST['func'], $_POST['arg']);?>"
    r = detect_webshell_functions(body)
    assert r is not None
    # call_user_func 是函数名, 但模式只匹配第一个 $_POST (func)
    assert "call_user_func" in r["functions"]
    assert "func" in r["passwords"]


def test_php_eval_base64_obfuscated():
    """eval(base64_decode($_POST['x']))"""
    body = b"<?php eval(base64_decode($_POST['x']));?>"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "eval" in r["functions"]
    assert "x" in r["passwords"]


def test_php_file_put_contents():
    """file_put_contents + $_POST"""
    body = b"<?php file_put_contents('1.php', $_POST['content']);?>"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "file_put_contents" in r["functions"]
    assert "content" in r["passwords"]


def test_php_multiple_passwords():
    """多个 $_POST 出现 → 收集多个密码"""
    body = b"<?php eval($_POST['cmd']);system($_POST['exec']);?>"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "cmd" in r["passwords"]
    assert "exec" in r["passwords"]


def test_php_no_match():
    """普通 PHP 代码不匹配"""
    body = b"<?php echo 'Hello, World!'; ?>"
    r = detect_webshell_functions(body)
    assert r is None


def test_php_only_text():
    """纯文本"""
    body = b"just some text without PHP"
    r = detect_webshell_functions(body)
    assert r is None


# ============== ASPX 模式 ==============

def test_aspx_eval_request():
    """eval(Request["pass"])"""
    body = b'<%@ Page Language="C#"%><%eval(Request["pass"])%>'
    r = detect_webshell_functions(body)
    assert r is not None
    assert "eval" in r["functions"]
    assert "pass" in r["passwords"]
    assert r["language"] == "aspx"


def test_aspx_eval_request_item():
    """eval(Request.Item["pwd"])"""
    body = b'<%eval(Request.Item["pwd"])%>'
    r = detect_webshell_functions(body)
    assert r is not None
    assert "pwd" in r["passwords"]


def test_aspx_eval_request_single_quote():
    """eval(Request['cmd'])"""
    body = b"<%eval(Request['cmd'])%>"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "cmd" in r["passwords"]


# ============== JSP 模式 ==============

def test_jsp_request_get_parameter():
    """request.getParameter('cmd')"""
    body = b'<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'
    r = detect_webshell_functions(body)
    assert r is not None
    assert "exec" in r["functions"]
    assert "cmd" in r["passwords"]
    assert r["language"] == "jsp"


def test_jsp_request_get_parameter_values():
    """request.getParameterValues('cmd')[0]"""
    body = b'<%String[] c=request.getParameterValues("cmd");%>'
    r = detect_webshell_functions(body)
    assert r is not None
    assert "cmd" in r["passwords"]


# ============== 边界情况 ==============

def test_empty_body():
    assert detect_webshell_functions(b"") is None


def test_none_body():
    assert detect_webshell_functions(None) is None


def test_binary_body_with_text():
    """二进制 body (multipart file part) 含文本 PHP 代码"""
    body = b"\x00\x01\x02<?php eval($_POST['cmd']);?>\x00\xff"
    r = detect_webshell_functions(body)
    assert r is not None
    assert "eval" in r["functions"]
    assert "cmd" in r["passwords"]


# ============== extract_webshell_from_multipart_body ==============

def test_extract_from_multipart():
    """multipart body 里有文件 part 含 webshell"""
    multipart = (
        b"------BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="title"\r\n'
        b"\r\n"
        b"My Article\r\n"
        b"------BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="1.php"\r\n'
        b"Content-Type: application/octet-stream\r\n"
        b"\r\n"
        b"<?php @eval($_POST['cmd']);?>\r\n"
        b"------BOUNDARY--\r\n"
    )
    results = extract_webshell_from_multipart_body(multipart)
    assert len(results) == 1  # 只文件 part
    assert "eval" in results[0]["functions"]
    assert "cmd" in results[0]["passwords"]


def test_extract_from_multipart_no_file():
    """multipart 但没文件 part (纯表单)"""
    multipart = (
        b"------BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="title"\r\n'
        b"\r\n"
        b"My Article\r\n"
        b"------BOUNDARY--\r\n"
    )
    results = extract_webshell_from_multipart_body(multipart)
    assert results == []


def test_extract_from_multipart_empty():
    assert extract_webshell_from_multipart_body(b"") == []
    assert extract_webshell_from_multipart_body(None) == []