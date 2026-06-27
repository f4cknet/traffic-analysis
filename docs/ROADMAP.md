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

**目标**：用 scapy 搭建流量分析工具框架，落地第一个功能模块 —— **通过 HTTP header / UA 识别攻击者使用的扫描器**。

**设计原则**：
- 遵循 [docs/principles.md](principles.md) §1：scapy 替代 tshark，Python package 优先
- 框架可扩展：后续 webshell / 攻击链模块都基于这套框架叠加
- 规则数据驱动：scanners.yaml 加一行就能识别新扫描器

**交付**：
- [ ] `tools/src/mvp_v3.py` — scapy 主分析器（frame 级 HTTP 解析 + 三段式匹配 + Markdown 报告）
- [ ] `tools/rules/scanners.yaml` — 扫描器规则库（搬旧 + 扩 nessus）
- [ ] `tools/requirements.txt` — 依赖锁定（scapy / PyYAML）
- [ ] `tools/generate_ssh_key.py` — 已存在的 dev 工具，迁入
- [ ] `examples/web_attack.md` — 真实题目题解（writeup）
- [ ] `examples/web_attack_report.md` — MVP 跑出的样例报告

**验收标准**：
- `pip install -r tools/requirements.txt` 一条命令搞定依赖
- `python tools/src/mvp_v3.py --pcap <path>` 跑 web_attack.pcap 出 Markdown 报告
- 攻击者 IP `192.168.94.59`、扫描器 AWVS + sqlmap、时间线全部正确
- YAML 加新规则能立即生效（无需改 Python 代码）
- 跨平台：Windows / Linux / macOS 同一份代码可跑

---

## v0.3.0 — HTTP body 提取

**目标**：解决"flag 在响应 body 里"的场景。

**交付**：
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
