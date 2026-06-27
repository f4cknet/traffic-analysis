# tests/ - 单测说明

测试 `tools/src/analyzer_core.py` 的纯 Python 逻辑。不依赖 pcap 文件。

## 跑测试

```bash
# 装 pytest (开发时)
pip install pytest

# 跑全部测试
cd tools && python -m pytest tests/

# 跑单个文件
python -m pytest tests/test_match_scanner.py -v
```

## 覆盖范围

| 文件 | 测什么 |
|---|---|
| `test_load_rules.py` | YAML 加载、字段完整、预编译正则、nessus 在内 |
| `test_match_scanner.py` | UA / header / payload 三段式触发、组合、weight 累加、不命中 |
| `test_analyze.py` | 全量聚合、攻击者评分、攻击类型分类、浏览器 UA 判断 |
| `test_render.py` | Markdown 输出文件存在、关键字段齐全 |

## 设计原则

- **不依赖 pcap**: 用纯 dict fixture 测，pytest 跑得快（< 1 秒）
- **不依赖 scapy / tshark**: 测的是共享逻辑，后端可换
- **fixture 集中**: 重复用到的扫描器规则 / sample records 在 `conftest.py`