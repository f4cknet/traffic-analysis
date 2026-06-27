# Traffic Analysis Toolkit

> CTF 应急响应 - 流量分析自动化工具集

针对**应急响应流量分析**。区别于传统 CTF 找 flag，应急类题目的答案形式是：

- 攻击者使用的**扫描器**类型
- 黑客**登录后台** + 用了什么**凭证**
- **webshell 文件名** / **上传时间** / **密码**
- 攻击链还原 / **时间线**

## 核心特性

- 🚀 **协议层精准识别**：按协议层字段（UA / 自定义 header / payload）分类匹配，避免字符串搜索的字段歧义
- 📋 **三段式证据等级**：UA 字段（强）/ 自定义 header（强）/ URI payload（弱辅证）
- 🔌 **规则可扩展**：所有分析模块（scanners / login paths / webshell paths / 字段别名）都是 YAML，加一条规则即可识别新目标
- 🚫 **Query 污染防护**：payload 段只看 URI path，不含 query string —— 防题目故意诱导
- 🎯 **三重过滤（login-analyze）**：POST + 命中登录接口 + 响应码 ∈ {302, 303} → 精确锁定真登录成功
- 🔑 **字段别名 yaml 化（credential-analyze）**：username / password / webshell 密码/命令都靠 YAML 别名表扩展
- 🧠 **代码内容解析（webshell-analyze）**：从 `<?php @eval($_POST[1234]);?>` 直接抽出密码，不靠 URL 参数
- 📊 **模块化**：按分析类型分 module（scanner / loginpath / cred / webshell），共享代码抽到 core

## 快速开始

### 安装

```powershell
# 1. 克隆仓库
git clone git@github.com:f4cknet/traffic-analysis.git
cd traffic-analysis

# 2. 安装 Python 依赖
pip install -r requirements.txt -r requirements-dev.txt

# 3. 准备 pcap 文件（不入仓库, 单独放在本地）
#    e.g. copy 到 D:\ctf\xxx.pcap
```

### 跑分析（4 个 module）

```powershell
# ① 扫描器识别 (默认 module) — 答"用了什么扫描器"
python src/analyze.py --pcap web_attack.pcap
# 等价: python src/analyze.py --pcap web_attack.pcap -m scanner

# ② 登录后台检测 — 答"哪些是登录后台 + 哪些 IP 探测了"
python src/analyze.py --pcap web_attack.pcap -m loginpath

# ③ 登录凭证提取 — 答"哪些凭证被服务端接受 (302/303) + 用了什么账号密码"
python src/analyze.py --pcap web_attack.pcap -m cred
# 自定义登录成功状态码 (RESTful API 场景 200 算成功):
python src/analyze.py --pcap api.pcap -m cred --login-success-code 200

# ④ webshell 专项 — 答"上传了哪个 webshell + 文件名 + 上传时间 + 密码"
python src/analyze.py --pcap web_attack.pcap -m webshell
```

### 自定义规则

```powershell
# 用你自己的 yaml 规则库
python src/analyze.py --pcap x.pcap --rules my_scanners.yaml
```

### 跑测试

```powershell
# 跑所有 module 的单测 (234 个, 0.18s)
python -m pytest src/

# 单独跑某个 module
python -m pytest src/module/webshell_analyze/test/
```

## 各模块输出对照表（以 web_attack.pcap 为例）

| Module | CLI | 答的题 | v0.5.1 实际输出 |
|---|---|---|---|
| `scanner` | `-m scanner` | 用了什么扫描器 | AWVS (header 命中 352) + sqlmap (UA 命中 6)，攻击者 192.168.94.59 |
| `loginpath` | `-m loginpath` | 哪些登录后台 | `/admin/login.php?rec=login` (2822 POST 命中) |
| `cred` | `-m cred` | 哪些账号密码被接受 | `admin/admin!@#pass123` (16:03 302) + `人事/hr123456` (14:35 302) |
| `webshell` | `-m webshell` | 上传了哪个 webshell + 密码 | `1.php` (16:12:49 上传) → eval → 密码 `1234` |

## 文档导航

| 文档 | 内容 |
|---|---|
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | 题目类型、答案形式、判据等级 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 工具架构、数据流、模块划分 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 迭代计划，每个版本交付什么 |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | 版本变更记录 |
| [docs/evidence-rules.md](docs/evidence-rules.md) | 扫描器判据等级详解（强/中/弱） |
| [docs/principles.md](docs/principles.md) | 项目铁律（工具选型、跨平台、依赖管理） |

## 当前状态

**v0.5.1** — 四个 module 全部端到端验证:

| Module | 版本 | 状态 |
|---|---|---|
| scanner-analyze | v0.2.0 | ✅ 已发布 |
| login-analyze | v0.3.0 | ✅ 已发布（双重过滤 + longest-match-first） |
| credential-analyze | v0.4.2 | ✅ 已发布（字段别名 yaml 化 + `--login-success-code` 参数） |
| webshell-analyze | v0.5.1 | ✅ 已发布（multipart 上传 + 代码内容解析） |

**端到端 web_attack.pcap 完整攻击链**（v0.3.0 → v0.4.2 → v0.5.1 链接）:

```
14:35  伴攻 192.168.94.233  登录成功 (人事/hr123456)            ← v0.4.2 答
16:03  主攻 192.168.94.59   登录成功 (admin/admin!@#pass123)     ← v0.4.2 答
16:12  主攻  上传 1.php (eval($_POST[1234])) 到 /admin/...     ← v0.5.0 + v0.5.1 答
```

下一个迭代 v0.6.0 计划：多协议支持（SMB / FTP / MySQL / Redis）或 response body flag 扫描。详见 [docs/ROADMAP.md](docs/ROADMAP.md)。

## 关键洞察

1. **协议层匹配是基础**——不区分 UA 头 / URI / body 的字符串搜索无法可靠识别扫描器
2. **自定义 header 是金标准**——如 `Acunetix-Aspect: enabled` 这种字段是扫描器自报家门
3. **URI path 含工具名是弱辅证**——攻击 payload 含工具名不等于 UA 是该工具
4. **URI query string 不参与 payload 段匹配**——题目可能故意把扫描器关键字塞 query 参数诱导
5. **真"登录成功"只有 302/303**——form submit 场景 200 是回显登录失败页（凭证错误）；RESTful API 场景用 `--login-success-code 200` 自定义
6. **webshell 密码从代码 body 抽**——不是从 URL 参数（攻击者可能没访问过上传的 webshell）；匹配 `eval($_POST['xxx'])` / `assert($_POST['x'])` 等主流模式

详细判据见 [docs/evidence-rules.md](docs/evidence-rules.md)。