# 变更记录

格式基于 [Keep a Changelog](https://keepachangelog.com/)，版本遵循 [语义化版本](https://semver.org/)。

## [Unreleased]

### Added
- `docs/principles.md` — 项目铁律，第一条「Python package 优先于外部 CLI 工具」（scapy > tshark，PyYAML > yq，cryptography > ssh-keygen，dnspython > dig）

### Changed
- `docs/ARCHITECTURE.md` §4.1 从「为什么用 tshark 而不是 scapy」改为「默认 scapy，tshark 作降级」，遵循新铁律 §1
- `README.md` 关键洞察 #1 去掉 `strings + grep` 字眼，保留「协议层匹配」核心观点
- `README.md` 关键洞察 #4 删除（整条是讲 scapy vs strings 的组件描述，与新铁律冲突）
- `README.md` 核心特性去掉 `tshark` 字眼
- `README.md` 删除「工具结构（v0.2.0 起）」整段（列出 src/ rules/ generate_ssh_key.py 等内部组件）
- `README.md` 文档导航表新增 `principles.md` 入口

### 设计决策（更新）
- ~~tshark + Python~~ → **scapy + Python，tshark 降级**（见 [docs/principles.md](principles.md) §1）

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
