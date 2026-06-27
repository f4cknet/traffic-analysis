"""webshell_analyze/script/parser.py - webshell 内容解析

从上传的 body 内容里识别 webshell 函数调用 + 抽密码.

核心思路: 主流 webshell 都是"代码执行 + 用户输入"模式, 例如:
  - PHP:   eval($_POST['pass'])        /  assert($_POST['x'])        /  system($_GET['cmd'])
  - ASPX:  eval(Request["pass"])        /  <%eval(Request.Item["x"])%>
  - JSP:   Runtime.getRuntime().exec(request.getParameter("cmd"))

密码不是从 URL 参数找的 (攻击者可能没访问过上传后的 webshell), 而是从
**上传 body 里的代码** 推出来的 — 这才是关键洞察.

实战经验: 中国菜刀 / 蚁剑 / 冰蝎 / 哥斯拉 都用类似模式 (eval/assert + $_POST/$_GET).
"""
from __future__ import annotations

import re
from typing import Optional


# ============== 主流 webshell 函数字典 (参考 + 扩展) ==============

# 这些函数在 webshell 上下文里出现 = 高度可疑
# 正常 PHP 程序也可能用 system/exec 等 — 但配合 $_POST/$_GET 模式 = webshell
WEBSHELL_FUNCTIONS: tuple[str, ...] = (
    "eval",            # PHP 最常见
    "assert",          # PHP < 8 一句话
    "system",
    "exec",
    "passthru",
    "shell_exec",
    "popen",
    "proc_open",
    "pcntl_exec",
    "preg_replace",    # PHP < 7 with /e modifier
    "create_function",
    "array_map",       # 可作回调执行
    "array_filter",
    "call_user_func",
    "call_user_func_array",
    "file_put_contents",  # 配合 $_POST 可写文件
    "fwrite",             # 同上
    "include",         # 配合变量
    "require",         # 配合变量
)

# 语言标签
LANG_PHP = "php"
LANG_ASPX = "aspx"
LANG_JSP = "jsp"
LANG_UNKNOWN = "unknown"


# ============== PHP 密码正则 ==============

# 模式 1: 函数( $_POST/$_GET/$_REQUEST[...] )
_PHP_VAR_PATTERNS = r"\$_(?:POST|GET|REQUEST|SERVER|COOKIE|FILES|ENV)"
_PHP_QUOTED_KEY = r"""[\'"]?(\w+)[\'"]?"""  # 兼容 'xxx' / "xxx" / xxx / 1234

# eval / assert / system / exec 等"直接执行"类
PHP_EXEC_PATTERNS: list[re.Pattern] = [
    re.compile(
        rf"(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)"
        rf"\s*\(\s*{_PHP_VAR_PATTERNS}\s*\[\s*{_PHP_QUOTED_KEY}\s*\]",
        re.IGNORECASE,
    ),
]

# call_user_func / array_map 等"高阶函数"类
PHP_FUNC_PATTERNS: list[re.Pattern] = [
    re.compile(
        rf"(call_user_func|call_user_func_array|array_map|array_filter|create_function)"
        rf"\s*\(\s*{_PHP_VAR_PATTERNS}\s*\[\s*{_PHP_QUOTED_KEY}\s*\]",
        re.IGNORECASE,
    ),
]

# base64 / gzuncompress 包裹的 eval (常见混淆)
PHP_OBFUSCATED_PATTERNS: list[re.Pattern] = [
    # eval(base64_decode($_POST['x']))
    re.compile(
        rf"eval\s*\(\s*(?:base64_decode|str_rot13|gzuncompress|hex2bin|gzinflate)"
        rf"\s*\(\s*{_PHP_VAR_PATTERNS}\s*\[\s*{_PHP_QUOTED_KEY}\s*\]",
        re.IGNORECASE,
    ),
]

# 文件写入类 (file_put_contents + $_POST)
PHP_WRITE_PATTERNS: list[re.Pattern] = [
    re.compile(
        rf"(file_put_contents|fwrite)\s*\(\s*[^,]+,\s*{_PHP_VAR_PATTERNS}\s*"
        rf"\[\s*{_PHP_QUOTED_KEY}\s*\]",
        re.IGNORECASE,
    ),
]


# ============== ASPX 密码正则 ==============

ASPX_PASSWORD_PATTERNS: list[re.Pattern] = [
    # eval(Request["pass"])
    re.compile(
        r'eval\s*\(\s*Request\s*\[\s*[\'"]?(\w+)[\'"]?\s*\]',
        re.IGNORECASE,
    ),
    # eval(Request.Item["pass"])
    re.compile(
        r'eval\s*\(\s*Request\.Item\s*\[\s*[\'"]?(\w+)[\'"]?\s*\]',
        re.IGNORECASE,
    ),
    # eval(Request.QueryString["pass"])
    re.compile(
        r'eval\s*\(\s*Request\.QueryString\s*\[\s*[\'"]?(\w+)[\'"]?\s*\]',
        re.IGNORECASE,
    ),
    # eval(Request.Form["pass"])
    re.compile(
        r'eval\s*\(\s*Request\.Form\s*\[\s*[\'"]?(\w+)[\'"]?\s*\]',
        re.IGNORECASE,
    ),
]


# ============== JSP 密码正则 ==============

JSP_PASSWORD_PATTERNS: list[re.Pattern] = [
    # request.getParameter("cmd")
    re.compile(
        r'request\.getParameter\s*\(\s*[\'"](\w+)[\'"]\s*\)',
        re.IGNORECASE,
    ),
    # request.getParameterValues("cmd")[0] — 也兼容没 [ 的场景
    re.compile(
        r'request\.getParameterValues\s*\(\s*[\'"](\w+)[\'"]\s*\)',
        re.IGNORECASE,
    ),
]


# ============== 高层接口 ==============

def _decode_body(body_bytes: bytes) -> str:
    """解码 body 字节 → 字符串. UTF-8 优先, latin-1 兜底."""
    if not body_bytes:
        return ""
    try:
        return body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return body_bytes.decode("latin-1", errors="replace")


def detect_webshell_functions(body_bytes: bytes, content_type: str = "") -> dict | None:
    """
    检测 body 里是否包含 webshell 函数调用 + 抽密码.

    返回:
      None - 没匹配到任何 webshell 模式
      {
        'functions': ['eval', 'assert', ...],
        'passwords': ['pass', 'cmd', '1234', ...],
        'language': 'php' / 'aspx' / 'jsp' / 'unknown',
        'matches': [{'function': 'eval', 'password': 'pass', 'source': 'php_exec'}, ...],
      }

    实际场景:
      - eval($_POST['pass'])  → function='eval', password='pass'
      - @eval($_POST[1234]);  → function='eval', password='1234' (无引号, 数字键也支持)
      - assert($_POST['x'])   → function='assert', password='x'
      - eval(Request["pwd"])   → function='eval', password='pwd' (ASPX)
    """
    if not body_bytes:
        return None

    body_str = _decode_body(body_bytes)
    if not body_str:
        return None

    functions: list[str] = []
    passwords: list[str] = []
    matches: list[dict] = []

    def _add(func: str, pwd: str, source: str):
        func_l = func.lower()
        if func_l not in functions:
            functions.append(func_l)
        if pwd and pwd not in passwords:
            passwords.append(pwd)
        matches.append({"function": func_l, "password": pwd, "source": source})

    # 1. PHP 模式 (eval/assert/system/exec/passthru/shell_exec/popen/proc_open/pcntl_exec)
    for pattern in PHP_EXEC_PATTERNS:
        for m in pattern.finditer(body_str):
            _add(m.group(1), m.group(2), "php_exec")

    for pattern in PHP_FUNC_PATTERNS:
        for m in pattern.finditer(body_str):
            _add(m.group(1), m.group(2), "php_func")

    for pattern in PHP_OBFUSCATED_PATTERNS:
        for m in pattern.finditer(body_str):
            _add("eval", m.group(1), "php_obfuscated")

    for pattern in PHP_WRITE_PATTERNS:
        for m in pattern.finditer(body_str):
            _add(m.group(1), m.group(2), "php_write")

    # 2. ASPX 模式
    for pattern in ASPX_PASSWORD_PATTERNS:
        for m in pattern.finditer(body_str):
            _add("eval", m.group(1), "aspx_eval")

    # 3. JSP 模式
    for pattern in JSP_PASSWORD_PATTERNS:
        for m in pattern.finditer(body_str):
            _add("exec", m.group(1), "jsp_exec")

    if not functions and not passwords:
        return None

    # 判定语言 (按匹配数最多)
    php_count = sum(1 for m in matches if m["source"].startswith("php_"))
    aspx_count = sum(1 for m in matches if m["source"].startswith("aspx_"))
    jsp_count = sum(1 for m in matches if m["source"].startswith("jsp_"))

    if php_count >= aspx_count and php_count >= jsp_count and php_count > 0:
        language = LANG_PHP
    elif aspx_count >= jsp_count and aspx_count > 0:
        language = LANG_ASPX
    elif jsp_count > 0:
        language = LANG_JSP
    else:
        language = LANG_UNKNOWN

    return {
        "functions": functions,
        "passwords": passwords,
        "language": language,
        "matches": matches,
        "body_size": len(body_bytes),
    }


def extract_webshell_from_multipart_body(body_bytes: bytes) -> list[dict]:
    """
    multipart body 里可能有多个 part (form fields + 文件), 我们要的是
    包含 webshell 代码的那个 part.

    返回 [{'part_index': int, 'function': str, 'password': str, 'language': str, 'content': str}, ...]

    实战场景: form 表单 (title/cat_id/content) + 文件 part (1.php).
    我们只关心文件 part.
    """
    if not body_bytes:
        return []

    body_str = _decode_body(body_bytes)
    # 找 boundary
    boundary_match = re.search(r"boundary=([^;\s]+)", body_str[:300])
    if not boundary_match:
        # 没 boundary, 直接当单 part 处理
        result = detect_webshell_functions(body_bytes)
        if result is None:
            return []
        return [{"part_index": 0, **result, "content": body_str[:500]}]

    boundary = boundary_match.group(1).strip().strip('"')
    parts = body_str.split(f"--{boundary}")
    results = []
    for i, part in enumerate(parts):
        # 找 header 结束位置
        h_end = part.find("\r\n\r\n")
        if h_end < 0:
            continue
        header = part[:h_end]
        content = part[h_end + 4:]
        # 只要文件 part (有 filename 字段)
        if "filename" not in header.lower():
            continue
        # 抽 webshell
        part_bytes = content.encode("utf-8", errors="replace")
        result = detect_webshell_functions(part_bytes)
        if result is None:
            continue
        results.append({
            "part_index": i,
            **result,
            "content_preview": content[:500],
        })
    return results