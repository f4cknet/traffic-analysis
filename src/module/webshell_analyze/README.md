# webshell-analyze (v0.3.0+ 占位)

待 v0.3.0 落地。

## TODO

- `rules/webshell_patterns.yaml` — webshell 文件名 / 上传 / 访问特征
- `script/detector.py` — POST multipart 上传检测 + webshell 访问检测
- `script/aggregator.py` — 上传时间线 + 访问时间线
- `script/report.py` — 控制台高可疑结果 (webshell 文件名 + 上传时间 + 访问时间 + 密码参数)
- `test/` — pytest 单测

## 数据流

```
pcap
  │ core.pcap_parser.parse_records (共享)
  ▼
records
  │ detector.detect_webshell_uploads + detect_webshell_access
  ▼
上传事件 + 访问事件
  │ aggregator.build_timeline
  ▼
时间线 + 摘要
```

参考 `scanner-analyze/` 目录结构和模板。