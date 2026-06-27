# 变更记录

格式基于 [Keep a Changelog](https://keepachangelog.com/)，版本遵循 [语义化版本](https://semver.org/)。

## [Unreleased]

### Changed
- **login_analyze 双重过滤**: **状态过滤 (2xx/3xx) + HTTP 方法过滤 (POST-only)**
  - **状态过滤**: 用 `tcp.stream` 关联 request/response, 只保留 2xx/3xx 响应. 攻击者 404 扫描噪声被过滤.
  - **方法过滤**: 每条 rule 带 `methods` 字段 (默认 `[POST]`). POST 是登录提交凭证的金标准 — GET 只是看表单页, 不算"尝试登录".
  - **longest-match-first**: matcher 改用最长命中优先, 避免 yaml 顺序重叠 bug (e.g. `/console/login` 14 字 > `/login` 6 字, weblogic rule 胜出)
  - 报告输出从"10183 次访问" → "3559 次真找到" → **"2822 次真尝试登录"** (web_attack.pcap)
  - **最终结论**: 黑客真正尝试登录的接口 = **`/admin/login.php?rec=login`**
    - 192.168.94.59: 2819 次 POST (主攻击者)
    - 192.168.94.233: 3 次 POST (伴攻)
- **login_paths.yaml 重写**: **只保留真登录接口**, 删后台首页/注册/调试端点
  - 删除: `/admin/`、`/admin/index`、`/admin/manage`、`/wp-admin/`、`/dede/index.php`、`/dede/`、`/user/register`、`/actuator/`、`/swagger-ui`、`/kibana/`、`/flask debug` 等
  - 保留: `/login`、`/admin/login`、`/wp-login.php`、`/dede/login.php`、`/phpmyadmin/`、`/adminer.php` 等
  - **类别从 5 (admin/CMS/db/framework/app) 简化为 4 (login/CMS/db/framework)** — 砍掉冗余的 admin 和 app category
  - **每条 rule 加 `methods: [POST]` (或 [GET, POST] for wp-login 等支持 GET 表单的)**
  - **每条 rule 的 patterns 按"具体度倒序"排** (longest-match 兜底, 但 yaml 顺序也调好)
- **matcher.py 升级**: `match_login_path` 改 longest-match-first (避免 yaml 顺序重叠 bug)
- **records contract 升级**: `parse_records` 现在返回 `{requests, responses_by_stream}`
  - tshark 同时导出 `tcp.stream` + `http.response.code` 字段
  - module.analyze 接 `http_data` (而不是 records list), 自己取所需字段
  - scanner-analyze 接 http_data 只用 requests (兼容, 行为不变)
- **core/utils.py**: 新增 `SUCCESS_RESPONSE_CODES = {200, 201, 202, 204, 301-308}`

### Added
- 目录结构重构: `src/` 统一 + `module/{name}/{rules,script,test}/` 分层
  - `src/core/` — 跨 module 共享 (pcap_parser + utils)
  - `src/module/scanner-analyze/` — 第一个分析模块 (rules + script + test 自包含)
  - `src/module/webshell-analyze/` — 占位 (v0.3.0+)
  - `src/module/login-analyze/` — 占位 (v0.4.0+)
  - `src/extend-tools/tshark/` — 瘦身后 tshark (110MB)
  - `src/_debug/` — 调试脚本 (.gitignore)
- `src/analyze.py` 重写为 CLI dispatcher (`--module xxx`), 不再每个分析类型开 entry script

### Changed
- **BREAKING**: 项目根目录结构大调整
  - 删除 `tools/` 整个目录
  - 删除根目录 `extend-tools/` (移到 `src/extend-tools/`)
  - 删除 `tools/src/mvp_v3.py` / `mvp_v3_tshark.py` / `bench.py`
  - 拆分 `analyzer_core.py` 为 `src/core/utils.py` + `src/core/pcap_parser.py`
  - 拆分 scanner 业务代码为 `scanner-analyze/script/{matcher,aggregator,report}.py`
  - 移 tests 到 `scanner-analyze/test/`
- 依赖移到顶层: `requirements.txt` / `requirements-dev.txt` 不再放在 `tools/`
- 删 scapy 后端: v0.2.0+ 只保留 tshark (实测 12× 性能差距, 应急分析场景不可妥协)
- 删 Markdown 报告渲染: v0.2.0 只输出控制台"高可疑结果"摘要
- 修 URI query 污染: payload 段只看 URI path, 不含 query string

### Removed
- `tools/` 整个目录
- `analyzer_core.py` (拆为 src/core/ 多个文件)
- `render_md()` (控制台输出替代)

### 设计决策（更新）
- **目录组织**: 按业务分析类型分 module, 每个 module 自包含 rules + script + test; 共享代码放 src/core/
- **CLI 入口**: 单一 dispatcher (--module), 避免每个 module 一个 entry script
- **后端选型**: 仅 tshark, 不保留 scapy fallback (性能 12× 差距 + 应急场景对延迟敏感)

### Added (login-analyze)
- `src/module/login_analyze/` — 第二问"黑客扫描到的登录后台"模块
  - `rules/login_paths.yaml` — 5 类共 ~25 个登录后台路径模式 (admin/CMS/db/framework/tomcat)
  - `script/matcher.py` — 路径模式匹配 (基于 uri_path, 排除 query 干扰)
  - `script/aggregator.py` — 聚合 (path × IP 访问次数 × 时间范围)
  - `script/report.py` — 控制台 print_summary 输出答案
  - `test/` — pytest 单测
- `--module login-analyze` dispatcher route

### Added (credential-analyze) — v0.4.0
- `src/module/credential_analyze/` — 第三问"高度可疑登录凭证"模块
  - 复用 `login_paths.yaml` + longest-match matcher (跨 module 共享)
  - **三重过滤**: POST + 命中登录接口 + 响应 ∈ {200, 302, 303}
  - POST body 解析: application/x-www-form-urlencoded (multipart/JSON 留 v0.5.0+)
  - **字段别名识别**: username 别名 (user/name/login/email/uname/log/...) + password 别名 (pwd/passwd/pass/password/...), 大小写不敏感
  - 报告: 按 (path_id, username, password) 聚合 (弱密码字典爆破证据) + 攻击者画像 + 登录尝试时间线
  - `script/{matcher,aggregator,report,field_aliases}.py`
  - `test/` — pytest 61 个 (含 urlencoded 解析 / 字段识别 / 三重过滤 / 聚合 / 攻击者画像)
- `--module cred` dispatcher route (`src/analyze.py -m cred`)
- `pytest.ini` + `conftest.py` — pytest 9.x 配置 (`addopts = --import-mode=importlib` 解决多 module 同名 test 冲突)

### Changed (credential-analyze) — v0.4.0
- `src/core/pcap_parser.py` 扩展导出字段:
  - `http.content_type` — 区分 form-urlencoded / multipart / json
  - `http.file_data` — POST body 字节 (hex 编码)
  - request records 新增字段: `content_type` + `post_body_bytes`
- `src/core/utils.py` 新增 helper:
  - `hex_to_bytes(hex_str)` — tshark hex 字符串 → bytes
  - `decode_body_str(body_bytes, encoding_hint)` — bytes → str (UTF-8 / latin-1 fallback, 支持 Content-Type charset)
- `src/core/__init__.py` 导出新 helper
- `requirements.txt` 删 scapy 死依赖 (v0.2.0+ 已删 scapy 后端, CHANGELOG 早写了)

### Added (credential-analyze) — v0.4.1 字段别名 yaml 化
- `src/module/credential_analyze/rules/field_aliases.yaml` — **字段别名库驱动**:
  - 加新别名直接改 yaml, **无需改 Python 代码** (与 scanners.yaml / login_paths.yaml 同套路)
  - username 类 (18 个): `username / user / user_name / name / login / email / uname / account / userid / user_id / uid / admin / mobile / phone / tel / log / loginname / login_id`
  - password 类 (12 个): `password / passwd / pass / pass_word / pwd / passw / userpass / user_pass / loginpass / login_pass / secret / key`
  - yaml 顺序即优先级, 第一条命中胜出
  - 未来扩展 (e.g. `email / csrf_token / token` 等): 在 yaml 里加新类别键即可
- `field_aliases.py` 重构:
  - `load_field_aliases(path=None)` — 从 yaml 加载; path=None 或文件不存在时返回 DEFAULT 拷贝
  - `DEFAULT_FIELDS` — 兜底硬编码 (与 yaml 默认值保持一致, 含 user_name / pass_word snake_case 支持)
  - `find_field(form, category, field_aliases=None)` — 接受 yaml 字段别名表, 不传则用 DEFAULT
  - `USERNAME_FIELDS` / `PASSWORD_FIELDS` tuple 保留 (旧 API 兼容)
- 端到端测试更新: web_attack.pcap 报告头显示 `字段名按 yaml 别名表 (username×18 + password×12)`

### 端到端 web_attack.pcap 验证 (v0.4.1)
- **2815 条高度可疑登录尝试** (vs v0.4.0 hardcoded 的 2807 条, +8 条因 user_name/pass_word 覆盖新增)
- **2256 组独立凭证** (vs v0.4.0 的 790 组, **×2.86 倍**)
- **关键发现 (v0.4.1 更精确的攻击者画像)**:
  - 攻击者做了**账号枚举 + 密码字典爆破**: top 账号是 8 字符随机字符串 (`bktihthm`, `vahuxfwr`, `pmsgacvf`, `vojqbivv`, `fgwyslwc` 等) — 看起来是攻击者动态生成的字典账号
  - 高频密码仍以 `g00dPa$$w0rD` 为主 (top 组合 top1-4 都是这密码)
  - 这覆盖了 v0.4.0 没识别的请求 (之前因字段名不在 hardcoded 列表里被过滤)
- **运行命令**: `python src/analyze.py --pcap examples/web_attack.pcap -m cred`

### Added (credential-analyze) — v0.4.2 登录成功码可配置
- **`--login-success-code` CLI 参数** (analyze.py): 用户自指定"登录成功"的响应状态码
  - 逗号分隔: `--login-success-code 302,303` (默认, form submit 标准)
  - 单值: `--login-success-code 200` (RESTful API 风格)
  - 多值混合: `--login-success-code 200,201` (移动端 API)
- **修正默认 {200, 302, 303} → {302, 303}**: v0.4.0 把 200 也算"高度可疑"是错的, 200 在 form submit 场景是回显登录失败页. 真"登录成功"只能是 302/303 (跳转) 或 RESTful 200 (用户自指定).
- **模块 API 升级**:
  - `LOGIN_SUCCESS_RESPONSE_CODES_DEFAULT = frozenset({302, 303})` (新名, 准确)
  - `SUSPICIOUS_LOGIN_RESPONSE_CODES` 保留作向后兼容别名
  - `is_suspicious_login_success(rec, status, success_codes=None)` — 接 success_codes 参数
  - `collect_credential_attempts(http_data, paths_data, field_aliases=None, success_codes=None)`
  - `analyze(http_data, paths_data, field_aliases=None, success_codes=None)`
  - `print_summary(..., success_codes=None)`
- **fixture 全用 302**: 单测 attack_http_data 的 s1-s9 全部用 302 响应 (v0.4.1 还混用 200/302, v0.4.2 改为全部 302)

### 端到端 web_attack.pcap 验证 (v0.4.2 金标准登录成功)
- 默认 `--login-success-code 302,303` 过滤后: **只剩 5 条真登录成功尝试 / 2 组独立凭证**
- **这是用户问题的答案 — 攻击者真破解的账号密码**:
  - `192.168.94.59` (主攻) 16:03 16:11 两次成功: **`username=admin` + `password=admin!@#pass123`**
  - `192.168.94.233` (伴攻) 14:35 / 14:41 / 16:11 三次成功: **`username=人事` + `password=hr123456`** (中文账号!)
- **攻击时间线**: 伴攻 14:35 首次成功, 主攻 16:03 首次成功 → **约 1.5 小时破解周期**
- 对比 v0.4.1 (2815/2256): 噪声被彻底剥离, 5 条就是 5 条真登录成功.
- 对比默认 {200, 302, 303} (v0.4.1): 200 全部是回显登录失败页, 没一条是真成功.
- **运行命令**:
  ```bash
  # 默认 (form submit 场景)
  python src/analyze.py --pcap examples/web_attack.pcap -m cred

  # RESTful API 场景 (200 是登录成功)
  python src/analyze.py --pcap x.pcap -m cred --login-success-code 200

  # 移动端 API (200/201 都算)
  python src/analyze.py --pcap x.pcap -m cred --login-success-code 200,201
  ```

### 历史 Unreleased 改动 (本次重构前)

> 以下是重构前已 push 但还没发布的改动, 重构后全部并入新结构.

#### Added (历史)
- `docs/principles.md` — 项目铁律, 第一条「Python package 优先于外部 CLI 工具」(scapy > tshark, PyYAML > yq, cryptography > ssh-keygen, dnspython > dig)
- `docs/ARCHITECTURE.md` §3 模块划分扩展: `mvp_v3.py` CLI 接口 + scapy 解析流程 + frame 级 vs TCP 重组取舍
- `docs/REQUIREMENTS.md` §3.4 依赖管理节, 明确 `requirements.txt` 锁版本
- `docs/ROADMAP.md` v0.2.0 重新定义为首模块「扫描器识别」(scapy 主分析器 + scanners.yaml)
- `tools/src/extend-tools/tshark/` — 瘦身后的 tshark 4.6.6 二进制子集 (110MB / 50 文件), 从完整 Wireshark 安装包 (280MB / 1342 文件) 砍掉 GUI / 其他工具 / 协议模块 / codec 杂项
- `tools/tests/` — pytest 单测, 41 个测试覆盖 YAML 加载 / 三段式匹配 / 全量聚合 / URI 拆分 / query 污染防护
  - `conftest.py` — 共享 fixture
  - `test_load_rules.py` — YAML 加载 + 字段完整 + nessus 在内
  - `test_match_scanner.py` — 三段式触发 + weight 累加 + 边界 + query 污染防护
  - `test_analyze.py` — 全量聚合 + 攻击者评分 + URI 攻击类型分类
- `tools/requirements-dev.txt` — 开发依赖 (pytest)

#### Changed (历史)
- `docs/ARCHITECTURE.md` §3 模块划分扩展: CLI 接口 + scapy 解析流程 + frame 级 vs TCP 重组取舍
- `docs/REQUIREMENTS.md` §3.4 依赖管理节, `requirements.txt` 锁版本
- `docs/ARCHITECTURE.md` §4.1 翻转: tshark 默认 + scapy fallback (实测 12× 性能差距, 后续又被本次重构删除)
- `docs/ARCHITECTURE.md` §5 性能表更新 (tshark 9s vs scapy 110s)
- `docs/principles.md` §1.4.1 新增已触发的例外条款记录 (tshark 后端的性能证据)

#### Removed (历史, 重构前)
- `tools/src/mvp_v3.py` — 改名为 `analyze.py`
- `tools/src/mvp_v3_tshark.py` — 合并到 `analyze.py` 内部 (dict 路由)
- `tools/src/bench.py` — 一次性脚本, 移到 `tools/_debug/bench.py`
- 根目录 `extend-tools/wireshark/` — 移到 `tools/src/extend-tools/tshark/` 并瘦身

### Added (credential-analyze) — v0.5.0 webshell 专项 (第四问"webshell 文件名 + 上传时间 + 密码")
- `src/module/webshell_analyze/` — 第四模块, 复用 src.core.pcap_parser
  - `rules/webshell_paths.yaml` — 4 类共 ~50 个 webshell 路径模式:
    - `generic_php` (28 个): `/shell.php`, `/cmd.php`, `/c.php`, `/r57.php`, `/c99.php`, `/caidao.php` 等
    - `generic_jsp` (14 个): `/shell.jsp`, `/behinder.jsp`, `/ant.jsp`, `/godzilla.jsp` 等
    - `generic_aspx` (7 个): `/shell.aspx`, `/cmd.aspx`, `/cmd.asp` 等
    - `ctf_known_paths` (8 个): `/songgeshigedashuaibi/`, `/webshell/`, `/phpinfo.php` 等真实 CTF 老题路径
    - `upload_dir` (7 个): `/upload/`, `/uploads/`, `/userfiles/`, `/attachments/`, `/tmp/`, `/temp/` (排除 `/images/` `/img/` `/static/` `/assets/` 静态资源目录, 防误报)
  - `rules/webshell_fields.yaml` — 字段别名库 (yaml 驱动):
    - `password` 类 (10 个): `pass`, `pwd`, `password`, `key`, `code`, `x`, `z0/z1/z2`, `0` (蚁剑默认)
    - `cmd` 类 (10 个): `cmd`, `c`, `command`, `exec`, `run`, `action`, `do`, `query`, `sql`, `1` (蚁剑第二个字段)
  - `script/matcher.py`:
    - `is_multipart_upload(rec)` — Content-Type 判定
    - `parse_multipart_filename(body, content_type)` — multipart body 抽 filename (含空 filename 过滤, 大小写不敏感)
    - `match_webshell_path(uri_path, paths_data)` — longest-match-first
    - `extract_url_query(uri)` / `extract_urlencoded_params(body, content_type)` — 参数提取
    - `detect_upload(rec)` — multipart 上传 + filename 抽取
    - `detect_access(rec, paths_data, field_aliases)` — 路径命中 OR URL/body 参数含密码字段
  - `script/aggregator.py`:
    - `collect_uploads(http_data)` — 所有 multipart 上传 (按时间线)
    - `collect_accesses(http_data, paths_data, field_aliases)` — 所有 webshell 访问
    - `link_uploads_to_accesses(uploads, accesses)` — 关联 (filename 包含 + 时间在前)
    - `find_orphan_accesses(uploads, accesses)` — 找没匹配到上传的访问 (orphan)
    - `build_attacker_profiles(...)` — 按 IP 聚合
  - `script/report.py` — 控制台输出 ([1] 关联摘要 [2] 攻击者画像 [3] 关键结论 [4] 访问时间线)
- `--module webshell` dispatcher route (`src/analyze.py -m webshell`)
- 89 个单测全过 (multipart 解析 / URL 参数 / 字段别名 / 关联逻辑)

### 端到端 web_attack.pcap 验证 (v0.5.0)
- **1 条 multipart 上传**:
  - 文件名 `1.php` (2018-08-08 16:12:49, 192.168.94.59, 上传到 `/admin/article.php?rec=update`)
  - 这是攻击者上传的**真 webshell 文件**
- **后续访问 0 次** — 上传后没看到调用 (可能脚本没继续, 或 webshell 被访问但未在本 pcap 中捕获)
- **4099 条 URL 参数含密码字段的访问**:
  - 主要是攻击者用 `pwd=g00dPa$$w0rD` 探测多个 URL (脚本化 fuzzing)
  - 路径不命中 webshell_paths.yaml 的探测尝试
- **关键洞察**:
  - **真 webshell 上传已识别**: `1.php` 在 16:12:49 上传
  - **攻击链完整**: v0.4.2 找到的 `admin/admin!@#pass123` (16:03 登录成功) → v0.5.0 找到的 `1.php` 上传 (16:12, 9 分钟后) → 攻击者登录后台后立即上传 webshell
- **运行命令**: `python src/analyze.py --pcap examples/web_attack.pcap -m webshell`

## [0.1.0] - 2026-06-27

### Added
- 项目 README 入口
- `docs/REQUIREMENTS.md` — 题目类型、答案形式、判据等级
- `docs/ARCHITECTURE.md` — 工具架构、数据流、模块划分
- `docs/ROADMAP.md` — 迭代计划（v0.1.0 → v1.0.0）
- `docs/CHANGELOG.md` — 本文档
- `docs/evidence-rules.md` — 扫描器判据等级详解
- `.gitignore` — 排除 pcap/log/debug 脚本
- 仓库 `f4cknet/traffic-analysis` 初始化 + 首次 push

### 设计决策
- **三段式匹配**：UA (强) / header (强) / payload (弱辅证) — 区分判定证据和干扰项
- **YAML 规则库**：人类可读，扩展无需改代码
- **tshark + Python**：协议层精准识别，性能优先
- **大文件不入仓库**：pcap/log 用 `.gitignore` 排除

### 已知约束
- 仅 HTTP 协议（SMB/FTP/MySQL 等留待 v0.4.0）
- 仅 Windows + PowerShell 测试（Linux/macOS 留待 v1.0.0）
- 测试题 `web_attack.pcap` 174MB，不入仓库

## 历史

### 2026-06-26 之前（非本仓库）

工具原型在 `D:\ctf\20260625\tools\` 下验证：
- `mvp_v1.py` — 基础 tshark 提取 + CSV
- `mvp_v2.py` — 修 BOM 问题 + 补 AWVS payload 模式
- `mvp_v3.py` — 三段式匹配 + 自定义 header 解析

这些代码已在 `D:\ctf\20260625\web_acctack\web_acctack\web_attack.pcap` 上验证可工作（172MB，73万帧，7万 HTTP 请求），将作为 v0.2.0 迁入本仓库。

测试题关键结论（验证过）：
- 攻击者 IP: `192.168.94.59`
- 扫描器: Acunetix Web Vulnerability Scanner (AWVS) + sqlmap 1.2.3.50
- AWVS 自定义 header 命中 352 次
- X-Forwarded-For 注入 20952 次（AWVS 自动加）
- WebDAV PROPFIND 探测 3 次
- webshell 可疑路径: `/songgeshigedashuaibi/hello.html`
- AWVS 攻击密码: `082119f75623eb7abd7bf357698ff66c`
