# 变更记录

格式基于 [Keep a Changelog](https://keepachangelog.com/)，版本遵循 [语义化版本](https://semver.org/)。

## [Unreleased]

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
