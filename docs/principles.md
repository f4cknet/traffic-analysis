# 项目铁律

> 跨迭代生效的最高约束。任何代码、文档、工具选型冲突时，以本文件为准。

## 1. 工具选型：Python package 优先于外部 CLI 工具

### 1.1 核心原则

**能用 Python 包就用 Python 包，外部 CLI 工具只在 Python 生态解决不了时才退而求其次。**

### 1.2 为什么这样定

| 维度 | Python 包 | 外部 CLI 工具 |
|---|---|---|
| **可移植性** | `pip install` 跨 Windows / Linux / macOS 一致 | 每 OS 单独装、版本对齐、路径处理 |
| **单语言栈** | 错误处理、参数传递、异常捕获全在 Python 内部 | 跨进程 + 文本/JSON 序列化，容易踩编码和参数解析坑 |
| **可打包** | 能打成 wheel / PyInstaller exe，无需先装系统组件 | 必须先装 Wireshark / Nmap / ... 再装本工具 |
| **CI 友好** | `pip install -r requirements.txt` 一条命令搞定 | 需要额外系统包、容器镜像或 sudo |
| **依赖锁定** | `requirements.txt` / `pyproject.toml` 锁版本，行为可重现 | CLI 版本由系统决定，可能漂移 |
| **调试** | pdb / IDE 直接断点 | 只能看 stdout / 日志 |

### 1.3 当前选型优先级表

| 用途 | Python 包（首选） | 外部 CLI（降级） | 说明 |
|---|---|---|---|
| **pcap 解析** | **`scapy`** | tshark | scapy `pip install` 即用；tshark 需先装 Wireshark，体积大、版本漂移 |
| **HTTP 协议层字段提取** | `scapy` + `http-parser` / `mitmproxy` | tshark `-T fields` | 字段位置明确时优先 scapy；协议层深度依赖时降级 tshark |
| **DNS 协议解析** | `dnspython` | dig / nslookup | |
| **YAML 读写** | `PyYAML` | yq | |
| **SSH key 生成** | `cryptography` | ssh-keygen | 已落地，见 `tools/generate_ssh_key.py` |
| **HTTP 客户端** | `requests` / `httpx` | curl | |
| **终端彩色输出** | `rich` | 手写 ANSI | |
| **PCAPNG 写入** | `scapy.utils.PcapWriter` | editcap / mergecap | |

> **示例**：本项目当前所有 pcap 分析**默认走 scapy**；只有当 scapy 解析失败（罕见畸形包）才降级到 tshark。

### 1.4 例外情况（允许用外部 CLI 的场景）

只有满足以下任一条件时，**才**允许退到外部 CLI 工具：

1. **生态空白**：Python 生态确实没有等价物（如 `masscan` 这类极速扫描器、`editcap` 的 pcap 格式修复）
2. **性能差距 ≥ 10×** 且场景对延迟/吞吐敏感（且评估文档里写清楚为什么）
3. **临时调试**：一次性脚本，用完即弃，并打 `# TODO(replace): <用 X 包替代>` 标记

### 1.4.1 已触发的例外

**tshark 后端**（v0.2.0+）— 触发条件 §1.4 (2)「性能差距 ≥ 10×」：

- **Python 候选**：scapy
- **外部 CLI 候选**：tshark (Wireshark)
- **性能对比**（web_attack.pcap 174MB）：

| 后端 | parse 耗时 | 内存峰值 | 部署体积 |
|---|---:|---:|---:|
| scapy | ~110 s | ~6 GB | pip install (~10MB) |
| tshark | **~9 s** | **~150 MB** | extend-tools (110MB) |

- **差距**：12× 速度 + 40× 内存
- **决策**：v0.2.0+ **仅保留 tshark**, 删 scapy fallback (性能差距太大, 应急场景不可妥协)
- **可移植性损失**: 无 tshark 二进制时跑不动
- **补救**: v0.2.0 用户群是 CTF 应急分析师, Windows x64 为主; 跨平台留给 v1.0.0
- **ARCHITECTURE §4.1** 详细描述

### 1.5 退到外部 CLI 时的硬性要求

如果确实要调外部 CLI，**必须**满足：

- 调用前用 `shutil.which()` 检查存在，给出友好的安装指引
- **必须**有 Python 包的 fallback（自动降级），不能"在没装 Wireshark 的机器上完全跑不起来"
- 调用走 `subprocess.run([...], capture_output=True, text=True, encoding='utf-8')`，**不要**走 shell
- 路径用绝对路径或 `Path`，不要相信 PATH

### 1.6 对历史决策的影响

| 文档 | 旧决策 | 新决策 | 原因 |
|---|---|---|---|
| `ARCHITECTURE.md` §4.1 | "为什么用 tshark 而不是 scapy" | **默认 scapy，tshark 作降级** | scapy 跨平台一致；本铁律 §1.2 |
| `README.md` 关键洞察 #4 | "tshark 比 strings 精准 15-20 倍" | 改为"scapy 比 strings 精准 N 倍，且**无需装 Wireshark**" | 本铁律 §1.1 |
| `CHANGELOG.md` 设计决策 | "tshark + Python" | "scapy + Python，tshark 降级" | 本铁律 §1.1 |

---

## 2. 跨平台（待补）

> 待 v0.3.0 跨平台测试时落地。占位。

---

## 3. 依赖管理（待补）

> 待 requirements.txt / pyproject.toml 规范化时落地。占位。

---

## 4. 版本与提交（待补）

> 引用根目录 `AGENTS.md` 或团队约定。