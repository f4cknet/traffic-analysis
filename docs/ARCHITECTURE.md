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

### 3.1 `tools/src/analyze.py`（v0.2.0 主分析器）

主分析器。负责 pcap → 扫描器识别全流程。

**CLI 接口**：

```bash
python tools/src/analyze.py --pcap <file.pcap>
python tools/src/analyze.py --pcap <file.pcap> --backend scapy   # 显式切 scapy
python tools/src/analyze.py --pcap <file.pcap> --backend auto    # tshark 优先, 降级 scapy
```

参数：
- `--pcap`（必填）：pcap/pcapng 文件路径
- `--rules`（默认 `tools/rules/scanners.yaml`）：YAML 规则库
- `--out`（默认 `out/report_<backend>_<timestamp>.md`）：Markdown 报告输出路径
- `--backend`（默认 `tshark`）：`tshark` / `scapy` / `auto`
- `--tshark`（可选）：显式指定 tshark.exe 路径

**核心流程**：

```
pcap
  │ [backend: tshark | scapy] -> records
  ▼
records (list[dict])
  │ analyze (三段式 + 聚合 + 评分)
  ▼
stats dict
  │ render_md
  ▼
report.md
```

**后端选择**（默认 tshark）：
- **tshark**：libpcap 原生 C 解析，~9 秒/174MB pcap，性能优先
- **scapy**：纯 Python 包解析，~110 秒/174MB pcap，便携优先
- **auto**：tshark 可用就用 tshark，否则降级 scapy

切换后端不需要改代码逻辑 — 两实现都返回相同结构的 records list。

### 3.2 `tools/src/analyzer_core.py`

共享分析逻辑（不依赖 pcap 解析后端）：
- `load_rules(path)`：YAML 加载 + 预编译正则
- `match_scanner(rec, rules)`：单条记录三段式匹配
- `analyze(records, rules)`：全量聚合 + 攻击者评分
- `render_md(stats, rules, pcap, out)`：Markdown 报告渲染
- 攻击类型分类 + 浏览器 UA 判断工具

### 3.3 `tools/rules/scanners.yaml`

规则库（30 条）。每条规则结构：

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

### 3.4 `tools/src/extend-tools/tshark/`

瘦身后的 tshark 4.6.6 二进制子集（110MB / 50 文件），从完整 Wireshark 安装包 (280MB / 1342 文件) 砍掉 GUI / 其他工具 / 协议模块 / codec 杂项而来。

包含：
- `tshark.exe` 主程序
- `libwireshark.dll` (90MB) + `libwiretap.dll` + `libwsutil.dll` 核心三件套
- GLib / TLS / 字符编码 / 压缩库等系统依赖

仅 Windows x64。要在 Linux / macOS 上跑，需要按同样策略从对应平台安装包瘦身。

`analyze.py` 默认从 `tools/src/extend-tools/tshark/tshark.exe` 找 tshark。

### 3.5 `tools/tests/`

pytest 单测。覆盖：
- `test_load_rules.py` — YAML 加载 + 字段完整 + nessus 在内
- `test_match_scanner.py` — 三段式触发 + weight 累加 + 边界情况
- `test_analyze.py` — 全量聚合 + 攻击者评分 + URI 攻击类型分类
- `test_render.py` — Markdown 输出文件 + 关键字段齐全

跑测试：`pip install -r tools/requirements-dev.txt && python -m pytest tools/tests/`

### 3.6 `tools/requirements.txt` / `requirements-dev.txt`

依赖清单：
```
# requirements.txt (运行时)
PyYAML>=6.0                # 规则库加载 (tshark 后端)
scapy>=2.5.0               # scapy 后端 (可选, --backend scapy 才需要)

# requirements-dev.txt (开发时, 含 pytest)
pytest>=7.0
```

**注意**：tshark 后端不依赖 scapy。用户只用 tshark 就不需要装 scapy，可移植性更好。

### 3.7 `tools/generate_ssh_key.py`
开发辅助工具。生成 ed25519 SSH key（绕过 PowerShell 引号坑）。

## 4. 关键设计决策

### 4.1 pcap 解析：tshark 默认，scapy fallback

> 本决策触发 [docs/principles.md](principles.md) §1.4 例外条款（性能差距 ≥ 10×）。

**实测性能对比**（web_attack.pcap 174MB / 73万帧 / 71340 HTTP 请求）：

| 后端 | parse_pcap 耗时 | 内存峰值 | 部署体积 |
|---|---:|---:|---:|
| tshark | **~9 秒** | ~150MB | 110MB |
| scapy | ~110 秒 | ~6GB | `pip install scapy` 几 MB |

scapy 慢 **12 倍**且吃 6GB 内存 — 应急分析场景下不可接受。

**默认选 tshark 的理由**：
- **性能 12×**：libpcap 原生 C 解析 vs Python 逐帧 dissect
- **内存友好**：独立子进程，常驻 150MB
- **协议覆盖**：Wireshark 是行业标准，覆盖率高于 scapy 自定义解析
- **部署可控**：extend-tools/tshark/ 锁版本，行为可重现

**保留 scapy 作为 fallback**：
- 便携场景（无 extend-tools 时）：`--backend scapy` 切纯 Python 解析
- pcap < 50MB 时 scapy 也够用，不必为小文件启动外部进程
- 单测、CI：scapy 路径便于 mock 测试

**触发原则**（按 principles.md §1.4 修订）：
- pcap > 50MB → 默认 tshark（性能优先）
- pcap < 50MB → 可选 scapy（便携优先）
- tshark 不可用 → 自动降级 scapy（`--backend auto`）

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

基于 web_attack.pcap (174MB, 73万帧, 71340 HTTP 请求) 实测：

### 5.1 tshark 后端（默认）

| 阶段 | 耗时 | 备注 |
|---|---|---|
| tshark 导出 8 字段 | ~9 s | 单次子进程调用 |
| records 构造 (header 拆分) | ~2 s | Python 主导 |
| 规则匹配 + 计分 | < 1 s | 内存计算 |
| Markdown 渲染 | < 1 s | 文本生成 |
| **总计** | **~12 s** | 单次跑完 |

### 5.2 scapy 后端（fallback）

| 阶段 | 耗时 | 备注 |
|---|---|---|
| scapy rdpcap (174MB) | ~103 s | 一次性加载所有帧到内存 |
| HTTPRequest 过滤 + 字段提取 | ~5 s | frame 级遍历 |
| 规则匹配 + 计分 | < 1 s | 内存计算 |
| Markdown 渲染 | < 1 s | 文本生成 |
| **总计** | **~110 s** | 比 tshark 慢 9-12 倍 |

### 5.3 对比结论

- **大 pcap (> 50MB) 用 tshark**：性能 12× 优势，内存峰值差 40× (150MB vs 6GB)
- **小 pcap (< 10MB) 用 scapy 也可**：几秒完成，省去启动 tshark 子进程开销
- **单测/CI 用 scapy**：无需在测试环境部署 tshark 二进制

更详细的可执行对比见 `tools/_debug/bench.py`（一次性脚本，不入主分支）。

## 6. 扩展点

未来可扩展方向（按 [ROADMAP.md](ROADMAP.md)）：

- **新协议**：SMB/FTP/MySQL/Redis → 增加对应的 tshark 字段提取
- **新攻击模式**：DNS 隧道、ICMP 隧道 → 协议层 + 行为特征
- **自动答题**：从题目描述自动识别问题类型 → LLM 解析 + 工具调用
- **多 pcap 批量**：跨包关联 → 攻击者画像
