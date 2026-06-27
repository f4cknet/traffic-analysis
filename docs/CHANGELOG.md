# 变更记录

格式基于 [Keep a Changelog](https://keepachangelog.com/)，版本遵循 [语义化版本](https://semver.org/)。

## [Unreleased]

### Added
- `tools/src/extend-tools/tshark/` — 瘦身后的 tshark 4.6.6 二进制子集 (110MB / 50 文件)，从完整 Wireshark 安装包 (280MB / 1342 文件) 砍掉 GUI / 其他工具 / 协议模块 / codec 杂项
- `tools/tests/` — pytest 单测，48 个测试覆盖 YAML 加载 / 三段式匹配 / 全量聚合 / Markdown 渲染，0.09s 跑完
  - `conftest.py` — 共享 fixture
  - `test_load_rules.py` — YAML 加载 + 字段完整 + nessus 在内
  - `test_match_scanner.py` — 三段式触发 + weight 累加 + 边界
  - `test_analyze.py` — 全量聚合 + 攻击者评分 + URI 攻击类型分类
  - `test_render.py` — Markdown 输出文件 + 关键字段齐全
- `tools/requirements-dev.txt` — 开发依赖（pytest）
- `tools/tests/_README.md` — 单测说明

### Changed
- **BREAKING**: 主分析器从 `mvp_v3.py` 改名为 `analyze.py`；tshark 默认，scapy 作 `--backend scapy` fallback（不再每个后端开一个文件）
- `tools/src/` 新增 `analyzer_core.py` — 共享分析逻辑（load_rules / analyze / render_md / match_scanner），不再每个后端重复实现
- `tools/src/extend-tools/tshark/` 取代根目录 `extend-tools/wireshark/`（已删除）
- `tools/requirements.txt` 拆分：scapy 改为可选依赖（`--backend scapy` 才需要），tshark 后端仅需 PyYAML
- `docs/ARCHITECTURE.md` §3 模块划分重写（analyze / analyzer_core / extend-tools / tests / requirements 五段）
- `docs/ARCHITECTURE.md` §4.1 翻转：tshark 默认 + scapy fallback（实测 12× 性能差距）
- `docs/ARCHITECTURE.md` §5 性能表更新（tshark 9s vs scapy 110s）
- `docs/principles.md` §1.4.1 新增已触发的例外条款记录（tshark 后端的性能证据）

### Removed
- `tools/src/mvp_v3.py` — 改名为 `analyze.py`
- `tools/src/mvp_v3_tshark.py` — 合并到 `analyze.py` 内部（dict 路由）
- `tools/src/bench.py` — 一次性脚本，移到 `tools/_debug/bench.py`
- 根目录 `extend-tools/wireshark/` — 移到 `tools/src/extend-tools/tshark/` 并瘦身

### 设计决策（更新）
- ~~完全 scapy，no tshark 降级~~ → **tshark 默认 + scapy fallback**（实测性能 12× 差距触发 principles.md §1.4 例外条款）

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
