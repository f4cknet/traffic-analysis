# 变更记录

格式基于 [Keep a Changelog](https://keepachangelog.com/)，版本遵循 [语义化版本](https://semver.org/)。

## [Unreleased]

### Added
- `docs/principles.md` — 项目铁律，第一条「Python package 优先于外部 CLI 工具」（scapy > tshark，PyYAML > yq，cryptography > ssh-keygen，dnspython > dig）
- `docs/ARCHITECTURE.md` §3 模块划分扩展：`mvp_v3.py` 的 CLI 接口 + scapy 解析流程 + frame 级 vs TCP 重组取舍
- `docs/REQUIREMENTS.md` §3.4 依赖管理节，明确 `requirements.txt` 锁版本
- `docs/ROADMAP.md` v0.2.0 重新定义为首模块「扫描器识别」（scapy 主分析器 + scanners.yaml）

### Changed
- `docs/ARCHITECTURE.md` §4.1 从「默认 scapy + tshark 降级」改为「完全用 scapy」，v0.2.0 不引入 tshark 降级路径
- `docs/REQUIREMENTS.md` §3.3 兼容性需求去掉 tshark 依赖，§3.1 功能需求按模块拆分 v0.2.0 / v0.3.0+ 边界
- `docs/ROADMAP.md` 迭代总览更新（v0.1.0 → ✅ 已发布，v0.2.0 → 🚧 进行中）

### 设计决策（更新）
- ~~tshark + Python~~ → **完全 scapy**，无 tshark 降级（见 [docs/principles.md](principles.md) §1）

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
