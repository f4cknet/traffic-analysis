# login-analyze (v0.4.0+ 占位)

待 v0.4.0 落地。

## TODO

- `rules/brute_force_patterns.yaml` — 登录失败特征 / 常见用户名字典 / 常见登录路径
- `script/detector.py` — 高频登录失败检测 + 字典攻击检测 + 凭证填充检测
- `script/aggregator.py` — 攻击者聚合 + 时间线
- `script/report.py` — 控制台高可疑结果 (攻击者 IP + 失败次数 + 目标账号)
- `test/` — pytest 单测

## 数据流

```
pcap
  │ core.pcap_parser.parse_records (共享)
  ▼
records
  │ detector.detect_login_failures + detect_credential_stuffing
  ▼
登录事件
  │ aggregator.aggregate_by_ip + build_timeline
  ▼
攻击者排行 + 时间线
```

参考 `scanner-analyze/` 目录结构和模板。