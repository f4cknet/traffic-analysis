# 需求文档：CTF 应急流量分析工具

## 1. 背景

CTF 比赛中有一类题目叫**"应急响应"（Incident Response）**，与传统的 flag 隐藏题不同：
- 传统 CTF：题目会内置一个 flag 字符串（`flag{xxx}` 或类似格式），找到即可
- 应急响应：题目提供 pcap 流量包，问的是**取证类问题**

本题库专门针对**应急响应中的流量分析**子分类。

## 2. 题目类型与答案形式

### 2.1 常见题目分类

| 题目问什么 | 答案形式 | 难度 |
|---|---|---|
| 攻击者 IP | `192.168.x.x` | ★ |
| 目标服务器 IP | `192.168.x.x` | ★ |
| 攻击者使用的**扫描器** | `sqlmap` / `AWVS` / `Nmap` / 等 | ★★ |
| webshell 的**文件名** | `/upload/shell.php` | ★★★ |
| webshell 的**密码** | `cmd=id` / 自定义 | ★★★ |
| webshell **上传时间** | `2018-08-08 15:23:45` | ★★★ |
| webshell **首次访问时间** | 上面 +N 分钟 | ★★★ |
| 攻击链还原 | 多个时间点 + 多个 IP + 多个事件 | ★★★★ |

### 2.2 答案的统一特征

**没有统一的 flag 字符串**。每个题目的答案都不同，工具必须：
- 按结构化字段提取（UA、URI、header、payload）
- 按时间线排序事件
- 按"证据强度"判断结论可信度

## 3. 工具需求

### 3.1 功能需求

**v0.2.0 已完成**（首模块：扫描器识别）：
- [x] 用 tshark 解析 pcap/pcapng，提取所有 HTTP 请求（含自定义 header）
- [x] 按字段分类匹配：UA 字段 / 自定义 header / URI payload 三段式
- [x] YAML 规则库驱动，新增扫描器无需改代码
- [x] 输出控制台高可疑结果摘要（v0.2.0 砍掉 Markdown 报告渲染）
- [x] CLI 入口参数化（输入 pcap、规则文件、模块名均可指定，`-m xxx` dispatcher）

**v0.3.0 已完成**（第二模块：登录后台检测 `login-analyze`）：
- [x] 登录后台路径模式匹配（`login_paths.yaml`，22 条规则，4 类别）
- [x] **双重过滤**：响应状态 2xx/3xx（用 `tcp.stream` 关联 req/resp）+ HTTP 方法过滤（POST-only by default）
- [x] longest-match-first matcher（避免 yaml 顺序重叠 bug）
- [x] 输出控制台"黑客尝试登录的接口"摘要 + 攻击者画像

**v0.4.0+ 待办**（按依赖顺序）：
- [ ] webshell 上传时间轴分析（POST multipart 检测 + 时间线）
- [ ] webshell 内容分析（base64 解码、混淆识别、密码提取）
- [ ] 攻击链还原（跨 IP 跨时间窗事件关联）
- [ ] 支持 SMB / FTP / MySQL / Redis 等非 HTTP 协议
- [ ] 提取 HTTP body 找 flag 字符串
- [ ] 一键导出 HTTP 对象到目录
- [ ] 多 pcap 批量分析

### 3.2 性能需求

- 170MB pcap（含 7 万 HTTP 请求）全量分析 < 30 秒（tshark 默认后端实测 ~12 秒）
- 内存占用 < 500MB（tshark 子进程常驻 ~150MB）
- 报告生成 < 5 秒

### 3.3 兼容性需求

- Windows 10/11 + PowerShell（首要目标，已验证）
- Linux / macOS：analyze.py 同套代码可跑；extend-tools/tshark 子集需按平台重新瘦身
- Python 3.10+
- **依赖外部 CLI 工具**（tshark 4.6.6），触发 [principles.md](principles.md) §1.4 例外条款（性能 12× 差距）
- 不依赖 WSL

### 3.4 依赖管理

按 [principles.md](principles.md) §1，依赖通过 requirements 锁定：

**`requirements.txt`**（运行时）：
```
PyYAML>=6.0           # 规则库加载（必需）
```

> 注：v0.2.0+ 已删除 scapy 后端（详见 [principles.md](principles.md) §1.4.1），故运行时不再依赖 scapy。

**`requirements-dev.txt`**（开发时，含 pytest）：
```
-r requirements.txt
pytest>=7.0           # 单测框架
```

**`src/extend-tools/tshark/`**（v0.2.0+ 必需）：
- tshark 4.6.6 二进制子集（110MB / 50 文件）
- 仅 Windows x64；跨平台需单独处理

`pip install -r requirements.txt` 一条命令搞定，跨平台一致。

## 4. 关键判据等级

应急响应中识别"扫描器"靠的是**协议层字段**，不是字节级匹配。

| 优先级 | 判据 | 强度 | 例子 |
|---:|---|---|---|
| 1 | UA 头直接是工具标识 | ★★★★★ | `User-Agent: sqlmap/1.2.3.50` |
| 2 | 自定义 header 字段 | ★★★★★ | `Acunetix-Aspect: enabled` |
| 3 | 工具探针 URI（自命名测试） | ★★★ | `/acunetix-wvs-test` |
| 4 | URI 包含工具名 | ★★ | URL 里 `acunetix` 关键字 |
| 5 | Payload 含工具特征 | ★ | `md5(acunetix_wvs_security_test)` |

**关键洞察**：
- UA 字段命中 → **直接判定**
- 自定义 header 命中 → **直接判定**
- 仅 payload 命中 → **需结合其它特征**（请求频率、URI 多样性等）

详细判据规范见 [evidence-rules.md](evidence-rules.md)。

## 5. 非功能需求

- **可扩展性**：新增扫描器只需加 YAML 规则，不改代码
- **可重现性**：相同输入必须产生相同输出（去重排序稳定）
- **可审计性**：所有规则的命中样例必须可追溯到 pcap 中的具体帧
- **可分享性**：报告以 Markdown 格式，可直接贴到 writeup

## 6. 题目样例（v0.1.0 状态）

测试题：`D:\ctf\20260625\web_acctack\web_acctack\web_attack.pcap`（不入仓库）

**已验证答案**（v0.1.0 文档阶段）：
- 攻击者 IP: `192.168.94.59`
- 目标 IP: `192.168.32.189:80`
- 扫描器: Acunetix Web Vulnerability Scanner (AWVS)
- 附带使用: sqlmap 1.2.3.50#dev
- webshell 可疑路径: `/songgeshigedashuaibi/hello.html`
- AWVS 攻击密码 (header 中): `082119f75623eb7abd7bf357698ff66c`
- 攻击时间: 2018-08-08 14:35:16 ~ 16:20:25

完整题解样例将在 v0.2.0 工具迁移后写入 `examples/web_attack.md`。
