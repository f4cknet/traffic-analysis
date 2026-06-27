# Traffic Analysis Toolkit

> CTF 应急响应 - 流量分析自动化工具集

针对**长期项目应急分析类题目**的 pcap/pcapng 流量包分析工具。区别于传统 CTF 找 flag，应急类题目的答案形式是：

- 攻击者使用的**扫描器**类型
- **webshell 文件名**和**上传时间**
- webshell 的**密码**
- 攻击链还原 / **时间线**

## 核心特性

- 🚀 **协议层精准识别**：用 tshark 按 `http.user_agent` 和自定义 header 字段过滤，**不靠 `strings + grep`**（后者无法区分字段）
- 📋 **三段式证据等级**：UA 字段 (强) / 自定义 header (强) / URI payload (弱辅证)
- 🔌 **规则可扩展**：YAML 规则库，加一行就能识别新扫描器
- 📊 **自动报告**：Markdown 格式，含攻击时间线、payload 样例、关键证据

## 快速开始

```powershell
# 1. 克隆
git clone git@github.com:f4cknet/traffic-analysis.git
cd traffic-analysis

# 2. 准备 pcap 文件
#    (pcap 文件不入仓库, 单独放在本地)

# 3. 跑分析 (待 v0.2.0 工具迁移完成)
python tools\src\mvp_v3.py
```

## 文档导航

| 文档 | 内容 |
|---|---|
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | 题目类型、答案形式、判据等级 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 工具架构、数据流、模块划分 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 迭代计划，每个版本交付什么 |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | 版本变更记录 |
| [docs/evidence-rules.md](docs/evidence-rules.md) | 扫描器判据等级详解（强/中/弱） |

## 工具结构（v0.2.0 起）

```
traffic-analysis/
├── README.md
├── docs/                  # 文档优先
│   ├── REQUIREMENTS.md
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md
│   ├── CHANGELOG.md
│   └── evidence-rules.md
├── tools/
│   ├── generate_ssh_key.py  # SSH key 生成 (dev 工具)
│   ├── src/                 # 核心分析脚本
│   └── rules/               # 扫描器 YAML 规则
├── examples/              # 题目样例 + 题解
└── .gitignore             # 排除 pcap/log/debug
```

## 当前状态

**v0.1.0** - 项目骨架（仅文档）

下一次迭代 v0.2.0 将迁移 MVP v3 工具。

## 已知关键洞察

1. **`strings + grep` 不能用于识别扫描器**——它无法区分关键字在 UA 头、URI 还是响应 body
2. **自定义 header 是金标准**——`Acunetix-Aspect: enabled` 这类字段是扫描器自报家门
3. **URI 中的工具名是辅证而非判定依据**——攻击 payload 含工具名不等于 UA 是该工具
4. **tshark 走协议层**才能区分字段，比 strings 精准 15-20 倍

详细判据见 [docs/evidence-rules.md](docs/evidence-rules.md)。
