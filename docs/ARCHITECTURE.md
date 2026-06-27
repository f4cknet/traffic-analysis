# 架构设计

## 1. 总体架构

```
┌─────────────────────────────────────────────────────┐
│                    pcap/pcapng 输入                   │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  tshark 子进程（协议层解析）                          │
│  - http.user_agent / http.request.method / http.uri │
│  - http.request.line (含所有自定义 header)           │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  Python 主分析器 (MVP)                                │
│                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │  UA 匹配  │  │Header 匹配│  │Payload 匹配│         │
│  │  (强证据) │  │ (强证据) │  │  (弱辅证) │           │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
│       └──────────────┴──────────────┘                │
│                       │                              │
│                       ▼                              │
│              扫描器命中 (按段计分)                       │
│                       │                              │
│                       ▼                              │
│              攻击者 IP 排行 + 评分                     │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              Markdown 报告输出                        │
│  - 攻击者 IP 排行 (按评分)                            │
│  - 扫描器识别结果 (按段分类)                          │
│  - 攻击时间线                                        │
│  - 典型 payload 样例                                  │
│  - 关键证据 + 强度                                    │
└─────────────────────────────────────────────────────┘
```

## 2. 数据流

```
pcap
  │
  │ tshark -T fields
  ▼
tsv (frame.time_epoch | ip.src | ip.dst | method | uri | ua | request.line)
  │
  │ csv.DictReader
  ▼
records (list[dict])
  │
  │ parse_request_line → headers dict
  ▼
records with parsed_headers
  │
  │ match_scanner (YAML 规则)
  ▼
hits (按段计分)
  │
  │ aggregate by IP / scanner
  ▼
stats dict
  │
  │ render_md
  ▼
report_v3_<timestamp>.md
```

## 3. 模块划分

### 3.1 `tools/src/mvp_v3.py`（v0.2.0 迁移）
主分析器。负责：
- 调用 tshark 子进程
- 解析 http.request.line 拆出所有 header
- 三段式匹配（UA / header / payload）
- 计分 + 攻击者排序
- 输出 Markdown 报告

### 3.2 `tools/rules/scanners.yaml`
规则库。每条规则结构：

```yaml
- id: acunetix_wvs
  name: Acunetix Web Vulnerability Scanner (AWVS)
  category: web_vuln_scanner
  ctf_priority: 10
  description: 商业 Web 漏洞扫描器
  match:
    ua:
      - "acunetix_wvs_security_test"
    header:
      - "Acunetix-Aspect"
    payload_keywords:
      - "acunetix"
  weight:
    ua: 10
    header: 12
    payload: 1
```

### 3.3 `tools/generate_ssh_key.py`
开发辅助工具。生成 ed25519 SSH key（绕过 PowerShell 引号坑）。

## 4. 关键设计决策

### 4.1 pcap 解析：默认 scapy，tshark 作降级

> 本决策遵循 [docs/principles.md](principles.md) §1「Python package 优先于外部 CLI」。

- **默认走 scapy**：`pip install scapy` 即用，跨 Windows / Linux / macOS 一致，无需装 Wireshark
- **降级路径 tshark**：scapy 解析失败（畸形包、罕见协议层）时自动 fallback 到 `tshark -T fields`
- **可移植性优先**：scapy 行为可重现（`requirements.txt` 锁版本）；tshark 版本由系统决定，可能漂移
- **协议准确性**：scapy 自定义解析对 HTTP/HTTPS/DNS 主流字段够用；Wireshark 在私有/罕见协议更准，但这类场景**不是本项目 v0.2.0 范围**
- **性能**：scapy 在 170MB pcap 上 ~30s 完成（可接受），未来若性能瓶颈再评估切到 tshark 默认路径

### 4.2 为什么用 YAML 规则库
- 人类可读，加新扫描器无需改代码
- 易于版本控制和审查
- 可在社区共享和扩展

### 4.3 为什么三段式匹配
- 字符串级匹配（`strings + grep`）无法区分字段位置
- 协议层匹配必须按字段分类
- 三段式明确区分"判定证据"和"干扰项"

### 4.4 为什么不用 `tshark -V` 全量输出
- `tshark -V` 输出每个包的完整协议树，文本量爆炸（170MB pcap → 几 GB）
- 用 `-T fields -e <field>` 按需提取字段，性能和可解析性最佳
- 用 `http.request.line` 一次性拿到所有自定义 header，避免枚举未知 header

## 5. 性能特征

基于 web_attack.pcap (174MB, 73万帧, 7万 HTTP 请求) 实测：

| 阶段 | 耗时 | 备注 |
|---|---|---|
| tshark 导出 7 字段 | 8.5s | 单次调用 |
| CSV 解析 + header 拆分 | 3s | Python 主导 |
| 规则匹配 + 计分 | < 1s | 内存计算 |
| Markdown 渲染 | < 1s | 文本生成 |
| **总计** | **~12s** | 单次跑完 |

## 6. 扩展点

未来可扩展方向（按 [ROADMAP.md](ROADMAP.md)）：

- **新协议**：SMB/FTP/MySQL/Redis → 增加对应的 tshark 字段提取
- **新攻击模式**：DNS 隧道、ICMP 隧道 → 协议层 + 行为特征
- **自动答题**：从题目描述自动识别问题类型 → LLM 解析 + 工具调用
- **多 pcap 批量**：跨包关联 → 攻击者画像
