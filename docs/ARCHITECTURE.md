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

### 3.1 `tools/src/mvp_v3.py`（v0.2.0 主分析器）

主分析器。负责 pcap → 扫描器识别全流程。

**CLI 接口**：

```bash
python tools/src/mvp_v3.py \
    --pcap <path/to/file.pcap> \
    --rules tools/rules/scanners.yaml \
    --out report_<timestamp>.md
```

参数：
- `--pcap`（必填）：pcap/pcapng 文件路径
- `--rules`（默认 `tools/rules/scanners.yaml`）：YAML 规则库
- `--out`（默认 `out/report_v3_<timestamp>.md`）：Markdown 报告输出路径

**核心流程**：

```
pcap
  │ scapy.rdpcap
  ▼
pkts (frame list)
  │ filter haslayer(HTTPRequest)
  ▼
HTTP requests list
  │ 对每个请求提取:
  │   - 已知字段 (Method, Path, Host, User-Agent)
  │   - 自定义 header 列表 (req.Headers)
  │   - 时间戳 (pkt.time)
  │   - 源 IP (pkt[IP].src)
  ▼
records (list[dict])
  │ match_scanner (三段式正则匹配)
  ▼
hits by scanner × segment
  │ aggregate by IP × scanner
  ▼
stats dict
  │ render_md
  ▼
report.md
```

**关键实现**：

- pcap 读取：`scapy.all.rdpcap(path)` 一次性加载
- HTTP 过滤：`pkts.filter(lambda p: p.haslayer(HTTPRequest))`
- 标准字段：`req.Method`, `req.Path`, `req.Host`, `req.User_Agent`
- 自定义 header：`req.Headers` 列表（每个元素是 `(name_bytes, value_bytes)` pair）
- 源 IP：`pkt[IP].src`（v4）/ `pkt[IPv6].src`（v6）
- 时间：`pkt.time`（epoch float）→ `datetime.fromtimestamp`

**Frame 级 vs TCP 重组**：

v0.2.0 用 frame 级解析（不开 TCPSession），原因：
- 大多数扫描器 HTTP request header 单个 TCP segment 装得下（< 8KB）
- 170MB pcap 一次性 TCPSession 重组会内存爆炸
- frame 级 99% 覆盖，应急分析题够用
- 漏掉的跨 segment 请求在 v0.3.0 评估是否加 TCPSession 模式

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

匹配字段说明：
- `match.ua`：正则匹配 User-Agent 字段（强证据）
- `match.header`：正则匹配"任意 header 名或值"（强证据）
- `match.payload_keywords`：字面量匹配 URI / 请求 body（弱辅证）
- `weight.ua / header / payload`：各段命中加分（默认 10/10/1）

### 3.3 `tools/requirements.txt`
依赖清单（pip 安装）：

```
scapy>=2.5.0          # pcap 解析 + HTTP 层
PyYAML>=6.0           # 规则库加载
```

### 3.4 `tools/generate_ssh_key.py`
开发辅助工具。生成 ed25519 SSH key（绕过 PowerShell 引号坑）。

## 4. 关键设计决策

### 4.1 pcap 解析：scapy（不引入 tshark）

> 本决策遵循 [docs/principles.md](principles.md) §1「Python package 优先于外部 CLI」。

v0.2.0 **完全用 scapy**，不引入 tshark 降级路径：
- **可移植性**：`pip install scapy` 跨 Windows / Linux / macOS 一致，无需装 Wireshark
- **单语言栈**：所有逻辑在 Python 内部，错误处理、异常捕获统一
- **依赖锁定**：`requirements.txt` 锁版本，行为可重现；tshark 版本由系统决定，可能漂移
- **协议准确性**：scapy 的 `HTTPRequest` 层对标准 + 自定义 header 都能识别（自定义进 `Headers` 列表），应急题够用
- **性能**：scapy frame 级解析在 170MB pcap 上预估 30-60s 可接受

**未来评估**：如果 v0.3.0+ 出现跨 segment 的 HTTP request 漏检问题，再考虑：
1. 加 `TCPSession` 模式（内存换准确性）
2. 极端情况 fallback 到 tshark（违反铁律 §1，需新写例外条款）

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
