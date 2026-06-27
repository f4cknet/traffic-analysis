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

```
analyzer-toolkit/
├── docs/                              # 文档
├── README.md
├── .gitignore
├── requirements.txt                   # 顶层运行时依赖
├── requirements-dev.txt               # 顶层开发依赖
├── out/                               # .gitignore 排除 (报告输出)
│
└── src/
    ├── analyze.py                     # CLI 入口 + module dispatcher
    │
    ├── core/                          # 跨 module 共享
    │   ├── __init__.py
    │   ├── pcap_parser.py             # tshark 子进程 + parse_records + URI 拆分
    │   └── utils.py                   # split_uri / ts_to_str / classify_uri / is_browser_ua
    │
    ├── extend-tools/
    │   └── tshark/                    # 瘦身后的 tshark 二进制子集 (110MB)
    │
    ├── _debug/                        # 调试脚本 (.gitignore 排除)
    │
    └── module/
        ├── scanner-analyze/           # 第一个分析模块
        │   ├── rules/
        │   │   └── scanners.yaml
        │   ├── script/
        │   │   ├── __init__.py        # 公开 API
        │   │   ├── matcher.py         # match_scanner (三段式匹配)
        │   │   ├── aggregator.py      # analyze + aggregate_per_ip_scanners
        │   │   └── report.py          # 控制台 print_summary
        │   └── test/                  # 单测紧耦合 module
        │       ├── conftest.py
        │       ├── test_load_rules.py
        │       ├── test_match.py
        │       └── test_split_uri.py
        │
        ├── webshell-analyze/          # 占位 (v0.3.0+)
        │   └── README.md              # TODO 说明
        │
        └── login-analyze/             # 占位 (v0.4.0+)
            └── README.md
```

### 3.1 `src/analyze.py` — CLI 入口 + dispatcher

**职责**：
- 解析 CLI 参数（`--pcap` / `--module` / `--rules`）
- 调用 `core.pcap_parser.parse_records()` 抽 HTTP 请求
- 根据 `--module` dispatch 到对应 module 的 analyzer
- 输出结果（默认控制台，可扩展 Markdown/JSON）

**CLI**：

```bash
# 扫描器识别 (默认 module)
python src/analyze.py --pcap <file.pcap>

# 显式指定 module
python src/analyze.py --pcap <file.pcap> --module scanner-analyze

# 自定义规则
python src/analyze.py --pcap <file.pcap> --rules custom.yaml
```

参数：
- `--pcap`（必填）：pcap/pcapng 文件路径
- `--module`（默认 `scanner-analyze`）：分析模块名
- `--rules`（可选）：自定义 YAML 规则库路径

**为什么 dispatcher 而不是多个 entry script**：

未来 webshell / login 都要 CLI 入口。如果每个 module 自己的 `analyze_xxx.py`，又退回到"每个变体一个文件"反模式。一个 `analyze.py --module xxx` dispatcher 更干净。

### 3.2 `src/core/` — 跨 module 共享

**`core/pcap_parser.py`**：
- `parse_records(pcap_path)` — 调 tshark + 拆 URI path/query → 返回 records list
- `find_tshark()` — 找 tshark.exe（项目内置 extend-tools/）

**`core/utils.py`**：
- `split_uri(uri)` — 拆 URI 为 (path, query)，防 query string 污染 payload 段
- `ts_to_str(epoch)` — epoch → 'YYYY-MM-DD HH:MM:SS'
- `classify_uri(uri)` — URI 攻击类型分类
- `is_browser_ua(ua)` — 判断是否正常浏览器 UA

**为什么独立 core/**：

scanner / webshell / login 都要从 pcap 抽 HTTP 请求（共享 pcap_parser）。URI 拆分、UA 判断、URI 攻击类型分类也是通用的（共享 utils）。不放 core/ 就要每个 module 复制 → DRY 违反。

### 3.3 `src/module/scanner-analyze/` — 扫描器识别模块

第一个分析模块。**自包含**：rules + script + test 都在 module 内。

**`rules/scanners.yaml`**：30 条扫描器规则。

**`script/`**：
- `matcher.py` — `match_scanner(rec, rules)` 单条记录三段式匹配（UA / header / payload）
- `aggregator.py` — `analyze(records, rules)` 全量聚合 + `aggregate_per_ip_scanners(stats, rules)` 每 IP 扫描器摘要
- `report.py` — `print_summary(...)` 控制台高可疑结果摘要
- `__init__.py` — 公开 API（re-export）

**`test/`**：pytest 单测（紧耦合 module）
- `conftest.py` — 共享 fixture
- `test_load_rules.py` — YAML 加载 + nessus 在内
- `test_match.py` — 三段式触发 + weight 累加 + query 污染防护
- `test_split_uri.py` — `split_uri` helper 单元测

跑测试：`python -m pytest src/module/scanner-analyze/test/`

### 3.4 `src/extend-tools/tshark/`

瘦身后的 tshark 4.6.6 二进制子集（110MB / 50 文件）。从完整 Wireshark 安装包 (280MB / 1342 文件) 砍掉 GUI / 其他工具 / 协议模块 / codec 杂项而来。

`analyze.py` 默认从 `src/extend-tools/tshark/tshark.exe` 找 tshark。

仅 Windows x64。要在 Linux / macOS 上跑，需要从对应平台安装包按同样策略瘦身。

### 3.5 `src/module/{webshell,login}-analyze/`

v0.3.0+ / v0.4.0+ 才填的占位目录。每个目录下放 `README.md` 说明 TODO。

按"业务分析按模块"组织：未来加新分析类型只需在 `src/module/` 下建新目录，复制 `scanner-analyze/` 模板填 rules + script + test 即可。

## 4. 关键设计决策

### 4.1 pcap 解析：tshark 单后端

> 本决策触发 [docs/principles.md](principles.md) §1.4 例外条款（性能差距 ≥ 10×）。

**实测性能对比**（web_attack.pcap 174MB / 73万帧 / 71340 HTTP 请求）：

| 后端 | parse 耗时 | 内存峰值 | 部署体积 |
|---|---:|---:|---:|
| tshark | **~9 秒** | ~150MB | 110MB |
| scapy (历史对比) | ~110 秒 | ~6GB | ~10MB |

scapy 慢 **12 倍**且吃 6GB 内存 — 应急分析场景下不可接受。**v0.2.0+ 只保留 tshark**，不再保留 scapy fallback：

- **性能 12×**：libpcap 原生 C 解析 vs Python 逐帧 dissect
- **内存友好**：独立子进程，常驻 150MB
- **协议覆盖**：Wireshark 是行业标准
- **部署可控**：extend-tools/tshark/ 锁版本，行为可重现

**trade-off**：
- 失去 scapy 的便携性（无 tshark 二进制时跑不动）
- 接受：v0.2.0 用户群是 CTF 应急分析师，机器性能 + Windows 为主
- 跨平台留给 v1.0.0：届时按平台瘦身 tshark 子集

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
