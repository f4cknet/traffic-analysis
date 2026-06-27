# 扫描器判据等级详解

## 核心原则

**字符串级匹配（`strings + grep`）不能用于识别扫描器**。原因：
- 关键字可能出现在请求头、URI、响应 body、自定义 header 等多个位置
- 工具在 URI 里的探针是"工具在探测"，不是"工具的标识"
- 必须按协议层字段分类匹配

## 等级表

### 等级 1：UA 头直接是工具标识（★ 强证据）

**判据**：`http.user_agent` 字段值直接包含工具名/版本号。

| 工具 | UA 例子 | 强证据 |
|---|---|---|
| sqlmap | `sqlmap/1.2.3.50#dev (http://sqlmap.org)` | ✓ |
| Nikto | `Mozilla/5.0 (compatible; Nikto/2.5.0)` | ✓ |
| WPScan | `WPScan 3.8.x (https://wpscan.org)` | ✓ |
| WhatWeb | `WhatWeb/0.5.5` | ✓ |
| Nmap NSE | `Mozilla/5.0 (compatible; Nmap Scripting Engine)` | ✓ |
| Wfuzz | `Wfuzz/2.4` | ✓ |
| gobuster | `gobuster/3.6` | ✓ |

**注意点**：
- sqlmap 自带 `sqlmap/` 标识，**几乎无法绕过**
- AWVS 默认 UA 伪装成 Chrome 41（2015 年），所以单看 UA 不能判定

### 等级 2：自定义 header 字段（★ 强证据）

**判据**：请求中包含工具特有的 header 名称或值。

| 工具 | 自定义 header | 强证据 |
|---|---|---|
| **AWVS** | `Acunetix-Aspect: enabled` | ✓ 100% |
| **AWVS** | `Acunetix-Aspect-Password: <md5>` | ✓ 100% |
| **AWVS** | `Acunetix-Aspect-Queries: filelist;aspectalerts` | ✓ 100% |
| Netsparker | `X-Scanner: Netsparker` | ✓ |
| Burp Suite | `X-Burp-...` 系列 | ✓ |
| OWASP ZAP | `X-ZAP-...` 系列 | ✓ |

**注意点**：
- 自定义 header 是**金标准**——工具开发者特制，绕过困难
- AWVS 必带 `Acunetix-Aspect` 系列，是判定 AWVS 的最可靠证据

### 等级 3：工具探针 URI（★★ 中等证据）

**判据**：URI 包含工具自有的测试路径或特征。

| 工具 | URI 例子 | 强度 |
|---|---|---|
| AWVS | `/acunetix-wvs-test-for-some-inexistent-file` | ★★ |
| sqlmap | `/usr/share/sqlmap/txt/common-tables.txt` | ★★ |
| WPScan | `/wp-content/plugins/xxx` | ★★ |

**注意点**：
- 这些是工具的"指纹路径"，攻击者通常不会改
- 单独命中 + UA 正常浏览器 → **可能**是工具也可能是巧合
- 单独命中 + 多 UA 轮换 + 高频 → **强**判定

### 等级 4：URI 包含工具名（★ 弱辅证）

**判据**：URI 中包含工具名或特征字符串。

| 例子 | 强度 |
|---|---|
| `id[$acunetix]=1` | ★ |
| `id=;print(md5(acunetix_wvs_security_test));` | ★ |
| `/sqlmap/` 出现在 URL 路径 | ★ |

**注意点**：
- 攻击 payload 含工具名 ≠ UA 是该工具
- **必须**配合等级 1/2/3 才能判定

### 等级 5：Payload 含工具特征（★ 弱辅证）

**判据**：请求体或参数包含工具特征。

| 例子 | 强度 |
|---|---|
| `print(md5(acunetix_wvs_security_test))` | ★ |
| `acunetix_wvs_security_test` | ★ |

**注意点**：
- 单独命中不可靠——很多工具用 `acunetix` 当漏洞验证 token
- **必须**配合等级 1/2/3 才能判定

## 攻击行为特征（额外佐证）

| 行为 | 含义 | 强度 |
|---|---|---|
| 同 IP 用 100+ 个不同 UA | **UA 轮换** 试图绕过 WAF | ★★★ |
| 同 IP 访问 1000+ 个不同 URI | **目录/漏洞扫描** | ★★★ |
| 请求里含 `X-Forwarded-For`、`Client-IP` | **XFF 注入** 绕 IP 限制 | ★★ |
| 含 `Acunetix-Aspect` 系列 | AWVS | ★★★★★ |
| 含 `Depth` header | **WebDAV PROPFIND** 探测 | ★★ |
| 大量 `OPTIONS` / `PROPFIND` 方法 | 服务探测 | ★★ |

## 综合判定流程

```
1. UA 字段命中？     → 直接判定
2. 自定义 header 命中？ → 直接判定
3. Payload 命中 + 攻击行为特征 ≥ 3 个？→ 高置信度判定
4. Payload 命中 + 攻击行为特征 1-2 个？ → 提示但需人工确认
5. 仅 Payload 命中？   → 仅作辅证
```

## 关键洞察汇总

1. **AWVS 默认 UA 是 Chrome 41**（2015）—— 看 UA 不能直接判定 AWVS
2. **AWVS 必带 `Acunetix-Aspect` header** —— 这是金标准
3. **sqlmap UA 自带 `sqlmap/`** —— 看 UA 就能直接判定
4. **URI 含 `acunetix` ≠ AWVS** —— 是攻击 payload，不是工具标识
5. **99% 扫描器**用轮换 UA 试图绕过 WAF，所以**只靠单条 UA 判定不可靠**

## 实战检查清单

拿到 pcap 后，按这个顺序查：

- [ ] 提取所有 UA，统计频率 → 找异常高频 UA
- [ ] 提取所有 `http.request.line`，找自定义 header
- [ ] 找 `Acunetix-Aspect` / `X-Burp-` / `X-ZAP-` 等特征 header
- [ ] 按 IP 聚合，看 UA 多样性 / URI 多样性 / 请求频率
- [ ] 找时间线最早的扫描器活动
- [ ] 找 webshell 上传 POST 请求
- [ ] 找 webshell 后续访问请求
