# 迭代路线图

## 迭代总览

| 版本 | 主题 | 状态 | 预计交付 |
|---|---|---|---|
| v0.1.0 | 项目骨架 | ✅ 已发布 | README + 5 份核心文档 + .gitignore |
| v0.2.0 | 首模块：扫描器识别 | 🚧 进行中 | scapy 主分析器 + scanners.yaml + 题解样例 |
| v0.3.0 | HTTP body 提取 | ⏳ | 一键导出 HTTP 对象到目录，找 flag |
| v0.4.0 | 多协议支持 | ⏳ | SMB / FTP / MySQL / Redis |
| v0.5.0 | webshell 专项 | ⏳ | POST multipart 检测 + 上传时间轴 |
| v0.6.0 | 自动化答题 | ⏳ | 从题目描述自动判定问题类型 |
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

## v0.4.0 — 多协议支持

**目标**：覆盖非 HTTP 类应急题（SMB 爆破、Redis 未授权、MySQL 拖库等）。

**交付**：
- [ ] SMB 协议分析（爆破、横向移动检测）
- [ ] FTP 协议分析（明文凭证、匿名登录）
- [ ] MySQL / Redis / MongoDB 协议分析
- [ ] DNS 隧道检测

---

## v0.5.0 — webshell 专项

**目标**：精确定位 webshell 文件名、上传时间、密码。

**交付**：
- [ ] POST multipart 上传检测（`Content-Type: multipart/form-data`）
- [ ] 文件写入时间轴（基于流量时间戳）
- [ ] webshell 访问时间轴（基于响应）
- [ ] webshell 内容提取（base64 / 混淆解码）
- [ ] 密码参数识别（cmd=, pass=, key= 等）

---

## v0.6.0 — 自动化答题

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
