# 迭代路线图

## 迭代总览

| 版本 | 主题 | 状态 | 预计交付 |
|---|---|---|---|
| v0.1.0 | 项目骨架 | ✅ 已发布 | README + 5 份核心文档 + .gitignore |
| v0.2.0 | 首模块：扫描器识别 | ✅ 已发布 | scanners.yaml + 三段式匹配 + 41 单测 |
| v0.3.0 | 第二模块：登录后台检测 (login-analyze) | ✅ 已发布 | login_paths.yaml + 双重过滤 + 38 单测 |
| v0.4.0 | 第三模块：登录凭证提取 (credential-analyze) | ✅ 已发布 | POST body 解析 + 字段别名 yaml + --login-success-code 参数 |
| v0.5.0 | 第四模块：webshell 专项 | 🚧 进行中 | multipart 上传 + URL 参数密码识别 + 时间线关联 |
| v0.6.0 | 多协议支持 | ⏳ | SMB / FTP / MySQL / Redis |
| v0.7.0 | 自动化答题 | ⏳ | 从题目描述自动判定问题类型 |
| v1.0.0 | 公开版本 | ⏳ | 文档 + 测试 + CI + 跨平台 |

---

## v0.1.0 — 项目骨架（本次迭代）

**目标**：建立可被他人阅读和维护的项目结构，文档优先。

**交付**：
- [x] `README.md` — 项目入口
- [x] `docs/REQUIREMENTS.md` — 题目类型、答案形式、判据
- [x] `docs/ARCHITECTURE.md` — 工具架构、数据流
- [x] `docs/ROADMAP.md` — 迭代计划（本文档）
- [x] `docs/CHANGELOG.md` — 变更记录
- [x] `docs/evidence-rules.md` — 判据等级详解
- [x] `.gitignore` — 排除 pcap/log/debug 脚本
- [x] GitHub 仓库 init + 第一次 commit + push

**不交付**（留给后续迭代）：
- MVP v3 工具代码（v0.2.0）
- 真实题目样例（v0.2.0）
- 测试用例（v0.2.0）

---

## v0.2.0 — 首模块：扫描器识别（本次迭代）

**目标**：落地第一个功能模块 —— **通过 HTTP header / UA 识别攻击者使用的扫描器**。同时建立**模块化项目结构**（`src/core/` + `src/module/{name}/`），后续 webshell / login / 攻击链模块直接套用。

**设计原则**：
- **目录组织**：按业务分析类型分 module，每个 module 自包含 rules + script + test；共享代码放 src/core/
- **CLI 入口**：单一 dispatcher (`-m xxx`)，避免每个 module 一个 entry script
- **后端选型**：仅 tshark，不保留 scapy fallback（实测 12× 性能差距 + 应急场景对延迟敏感）
- **规则数据驱动**：scanners.yaml 加一行就能识别新扫描器
- **测试覆盖**：单测紧耦合 module（`src/module/scanner_analyze/test/`），纯 dict fixture，0.1s 跑完
- **query 污染防护**：payload 段只看 URI path，不含 query string

**交付**：
- [x] `src/analyze.py` — CLI 入口 + dispatcher (`-m scanner`)
- [x] `src/core/` — 跨 module 共享 (pcap_parser + utils)
- [x] `src/module/scanner_analyze/` (CLI: `scanner`)
  - [x] `rules/scanners.yaml` — 30 条扫描器规则（搬旧 + 扩 nessus）
  - [x] `script/matcher.py` — `match_scanner` 三段式匹配（query 污染防护）
  - [x] `script/aggregator.py` — `analyze` 全量聚合 + `aggregate_per_ip_scanners`
  - [x] `script/report.py` — 控制台 `print_summary` 高可疑结果摘要
  - [x] `test/` — 41 个 pytest 单测（含 query 污染防护测试），0.05s 跑完
- [x] `src/extend-tools/tshark/` — 瘦身后的 tshark 4.6.6 (110MB / 50 文件)
- [x] `src/module/webshell_analyze/` — 占位 (CLI: `webshell`, v0.5.0+)
- [x] `src/module/login_analyze/` — 已落地 (CLI: `loginpath`)
- [x] `requirements.txt` / `requirements-dev.txt` — 顶层依赖
- [ ] `examples/web_attack.md` — 真实题目题解（writeup）

**验收标准**：
- ✅ `python src/analyze.py --pcap web_attack.pcap` 跑出控制台高可疑结果摘要
- ✅ 攻击者 IP `192.168.94.59`（71217 请求）、扫描器 AWVS (header 命中 352) + sqlmap (UA 命中 6)、XFF 注入 20952、WebDAV 3 — 全部正确
- ✅ YAML 加新规则能立即生效（无需改 Python 代码）
- ✅ query string 含 `acunetix` **不**触发 payload 段（query 污染防护）
- ✅ `pytest src/module/scanner_analyze/test/` 41 passed in 0.05s
- ✅ 解析耗时 ~12s（tshark 9s + analyze < 1s + print_summary < 1s）
- ⚠ 跨平台：当前 tshark 子集仅 Windows x64；Linux/macOS 需从对应平台安装包按同样策略瘦身

---

## v0.3.0 — login-analyze (已完成)

**目标**：v0.2.0 答了"用了什么扫描器"。v0.3.0 答**"扫描到哪些登录后台"**（第二问）。

**`login_analyze` (CLI: `loginpath`)**：

- `src/module/login_analyze/` — 登录后台路径模式匹配 + 攻击者画像
  - `rules/login_paths.yaml` — login/CMS/db/framework 4 类共 22 条（**只保留真登录接口**, 删后台首页/注册/调试端点）
  - 每条 rule 带 `methods: [POST]` (默认) 或 `[GET, POST]` (wp-login 等)
  - 输出：扫描到的登录后台路径 + 探测 IP + 探测次数 + 时间范围 + methods 标签
- pytest: 38 passed in 0.07s

跑命令：`python src/analyze.py --pcap x.pcap -m loginpath`

**`login_analyze` 数据流**：

```
pcap
  │ src.core.pcap_parser.parse_records (共享, 同时导 tcp.stream + http.response.code)
  ▼
{requests, responses_by_stream}
  │ matcher.match_login_path (longest-match-first, uri_path 匹配 login_paths.yaml)
  ▼
hits (path_id × IP × ts)
  │ aggregator 双重过滤: status 2xx/3xx AND method in rule.methods
  ▼
后台访问排行 + 攻击者画像
  │ report.print_summary (控制台, 含 methods 标签)
  ▼
答案
```

**端到端 web_attack.pcap 验证（v0.3.1 重过滤后）**：

| 过滤阶段              | 命中次数 | 噪声原因                          |
|---------------------|---------|----------------------------------|
| 过滤前                | 10183   | 攻击者 404 扫描 + 后台首页+注册+调试  |
| 仅过滤 404            | 3559    | 还含后台首页(/admin/, /dede/index)|
| **+ 过滤 GET-only**   | **2822**| **只剩真"登录尝试"(POST 提交凭证)** |

**最终答案**: 黑客真正尝试登录的接口 = `/admin/login.php?rec=login` (2822 次 POST, 192.168.94.59 + 192.168.94.233)

跑测试：`python -m pytest src/module/login_analyze/test/`

**交付**：
- [x] 响应状态过滤 (2xx/3xx only, 用 tcp.stream 关联)
- [x] HTTP 方法过滤 (POST-only by default)
- [x] matcher longest-match-first (避免 yaml 顺序重叠)
- [x] yaml 重写: 删后台首页/注册/调试端点, 每条 rule 加 methods 字段
- [ ] 响应 body 提取（scapy `HTTPResponse` 层 + reassembly）
- [ ] 响应 body 关键字扫描（flag 字符串正则）
- [ ] base64 编码 body 自动解码
- [ ] 图片/二进制文件单独目录保存

---

## v0.4.0 — credential-analyze (HTTP 登录凭证提取)

**目标**：v0.3.0 login-analyze 答了"哪些是登录后台"。v0.4.0 答**"哪些是高度可疑的登录成功尝试 + 提取的账号密码凭证"**。

**核心洞察**：
- v0.3.0 用双重过滤得到 2822 条 POST `/admin/login.php?rec=login` —— 都是"尝试"
- 现在需要再筛一层：**响应 200/302 才是"服务端接受"** —— 302 是登录成功跳转的金标准，200 是高度可疑（可能是回显带错误信息的登录页）
- POST body 通常带 `username=xxx&password=yyy`，**明文凭证可直接提取**

**核心逻辑**：
1. 复用 `login_paths.yaml`（同一套登录接口定义）+ longest-match matcher
2. 过滤：method=POST + 命中 login path + response.code ∈ {200, 302}
3. 凭证提取：解析 POST body（application/x-www-form-urlencoded）→ (username, password) 字段对
4. 字段识别：常见 username 别名（user / username / name / login / email / uname / account）+ password 别名（pwd / password / passwd / pass / passw），**第一条匹配的 username + 第一条匹配的 password**

**架构**：
- 新 module `src/module/credential_analyze/`（CLI: `cred`）
- `core/pcap_parser.py` 扩展：加 `http.file_data` 字段（POST body 字节 hex 编码）
- `credential_analyze/script/`：
  - `matcher.py` — 复用 longest-match 找登录接口 + body 解析
  - `aggregator.py` — 按 (path_id, username, password) 聚合 + 攻击者画像
  - `report.py` — 控制台输出每条可疑凭证（含 response.code + 时间戳 + IP）
  - `field_aliases.py` — 字段名别名表（hardcoded + 可 YAML 覆盖）
- yaml 复用 `login_paths.yaml`（不加新 yaml）

**输出示例**（伪）：
```
[!] 可疑登录成功尝试 (POST + 200/302):  共 3 条

  192.168.94.59  2018-08-08 14:42:15  POST /admin/login.php?rec=login  → 302
    username=admin  password=admin123
  
  192.168.94.59  2018-08-08 14:42:18  POST /admin/login.php?rec=login  → 302
    username=admin  password=qwerty
```

**测试**：
- pytest fixture：构造 POST dict 模拟请求 + body 字符串
- 验证：body 解析、字段识别、双重过滤、聚合

**已知限制**（v0.4.0 范围外，留后续）：
- multipart/form-data 不支持（webshell 上传也用 multipart，v0.6.0 统一处理）
- JSON body 不支持（API 类登录）
- 编码：先按 UTF-8 / latin-1 fallback；GBK 等中文编码按需加
- 同一个 body 多 username 字段取第一条（实际场景罕见）

**端到端验证**（web_attack.pcap）：
- login-analyze 已得 2822 POST `/admin/login.php?rec=login`
- 再过 200/302 过滤，期望得到"登录成功高度可疑"的子集
- 提取凭证后看 admin 用了哪些密码

---

## v0.5.0 — webshell 专项

**目标**：精确定位 webshell 的 **三问答案**：文件名、上传时间、密码。

**核心三问**：
1. **webshell 文件名** — 上传请求 body 里的 `filename=` 参数（multipart/form-data）
2. **上传时间** — 上传请求的 ts_epoch
3. **webshell 密码** — 后续访问时的密码参数（URL query 或 body：`pass=`, `pwd=`, `key=`, `code=`, `x=`, `cmd=` 等）

**核心洞察**：
- **上传 ≠ 确认是 webshell** — 普通 upload.php 上传图片不算。需要**后续被可疑访问**才确认（关联：先有 upload，再有 access）
- **multipart 解析**: tshark 已经导出 `http.content_type` + `http.file_data`（v0.4.0 加的）。v0.5.0 用 content_type 判定 multipart，再用自写的解析器抽 filename
- **密码识别**: 跟 credential_analyze 同套路 — yaml 驱动字段别名表（`pass / pwd / key / code / x / z0..z2 / cmd / c / command`），大小写不敏感

**架构**：
- 新 module `src/module/webshell_analyze/`（CLI: `webshell`）
- `rules/webshell_paths.yaml` — webshell 文件路径模式（`/shell.php`, `/cmd.php`, `/c.php`, `/ant.jsp`, `/behinder.jsp` 等通用名）+ 上传目录（`/upload/`, `/uploads/`, `/files/`）
- `rules/webshell_fields.yaml` — 密码/命令字段别名（yaml 化，参照 credential_analyze 的 field_aliases.yaml）
- `script/matcher.py`:
  - `is_multipart_upload(rec)` — Content-Type 是 multipart/form-data
  - `parse_multipart_filename(body, boundary)` — 从 multipart body 抽 `filename=`
  - `match_webshell_path(uri_path, paths_data)` — URI 路径匹配 webshell_paths.yaml
  - `extract_url_params(uri)` — 从 URL query 抽 pass/pwd/cmd 等
  - `extract_body_params(body, content_type)` — 从 urlencoded body 抽参数
- `script/aggregator.py`:
  - `collect_uploads(http_data)` — multipart 上传请求集合
  - `collect_accesses(http_data)` — URL 命中 webshell_paths.yaml 或 URL 参数含密码字段
  - `link_uploads_to_accesses(uploads, accesses)` — 时间线关联（先 upload 后 access）
- `script/report.py`: 控制台输出（时间线 + 文件聚合 + 攻击者画像）
- `script/field_aliases.py`: 字段别名 helper（参照 credential_analyze 的）

**输出示例**（伪）：
```
[!] 可疑 webshell 活动 (multipart 上传 + URL 参数访问):

  #1 /songgeshigedashuaibi/hello.html
     上传时间: 2018-08-08 15:42:13  IP: 192.168.94.59
     Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxxxx
     后续访问: 5 次
       2018-08-08 15:43:21  POST /songgeshigedashuaibi/hello.html  ?pass=xxx&cmd=whoami  (200)
       2018-08-08 15:44:05  POST /songgeshigedashuaibi/hello.html  ?cmd=id              (200)
       ...
```

**端到端验证**（web_attack.pcap）：
- 已知 webshell 路径：`/songgeshigedashuaibi/hello.html`（CTF 老题常见路径）
- 期望找到：上传请求时间 + 后续访问的 pass/cmd 参数

**测试**：
- pytest fixture: 构造 multipart 上传 + URL 参数访问请求
- 验证: filename 抽取、字段识别、关联

**已知限制**（v0.5.0 范围外，留后续）：
- binary body 完整提取（webshell 内容解码 base64）— v0.6.0
- response body 关键字扫描（flag）— v0.6.0
- 复杂 multipart 嵌套 — 当前只处理单层

**交付**：
- [x] multipart 上传检测（Content-Type 判定 + filename 抽取）
- [x] webshell 路径模式匹配（yaml 驱动）
- [x] URL 参数识别（pass/pwd/cmd/key/code/x 等）
- [x] body 参数识别（urlencoded + multipart 二进制）
- [x] 上传 + 访问 时间线关联
- [x] 攻击者画像（按 IP）
- [ ] webshell 内容 base64 解码（v0.6.0）
- [ ] response body flag 扫描（v0.6.0）

---

---

## v0.6.0 — 多协议支持

**目标**：覆盖非 HTTP 类应急题（SMB 爆破、Redis 未授权、MySQL 拖库等）。

**交付**：
- [ ] SMB 协议分析（爆破、横向移动检测）
- [ ] FTP 协议分析（明文凭证、匿名登录）
- [ ] MySQL / Redis / MongoDB 协议分析
- [ ] DNS 隧道检测

---

## v0.7.0 — 自动化答题

**目标**：从题目描述自动判定问题类型，给出结构化答案。

**交付**：
- [ ] 题目描述解析（关键词匹配 / LLM 调用）
- [ ] 答案模板生成（按问题类型）
- [ ] 答案可信度评分

---

## v1.0.0 — 公开版本

**目标**：可公开的成熟工具集。

**交付**：
- [ ] 完整文档（教程、API、FAQ）
- [ ] 单元测试覆盖率 > 80%
- [ ] CI（GitHub Actions）
- [ ] 跨平台（Windows / Linux / macOS）
- [ ] PyPI / pip 安装
- [ ] Docker 镜像

---

## 跨迭代原则

1. **每次迭代只交付一个目标**——避免一次改太多
2. **每个迭代结束**：
   - 更新 `CHANGELOG.md`
   - 跑通验证
   - commit + push
3. **跨迭代待办**写进 [ROADMAP.md](ROADMAP.md)，不要散落在 issue 或 TODO 注释
4. **bug 修复**可以独立 commit，但要在 CHANGELOG 注明
