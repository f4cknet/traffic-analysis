# extend-tools/tshark

瘦身后的 tshark 4.6.6 二进制子集。

## 体积

- 总计: 116MB (48 文件)
- 主要构成:
  - `libwireshark.dll` 90MB — Wireshark 核心协议解析库，无法再砍
  - GLib / PCRE / 字符编码 / TLS / GnuTLS / SSH 等系统依赖 ~20MB
  - `tshark.exe` 0.6MB

## 瘦身来源

从完整 Wireshark 4.6.6 (280MB, 1342 文件) 砍到 116MB，删除了：

- Wireshark 主 GUI (Wireshark.exe + Qt6 全套 + D3D)
- 其他工具集 (dumpcap / editcap / mergecap / sharkd / text2pcap 等)
- 协议模块目录 (snmp / protobuf / radius / snmp / lua plugins 等)
- 视频/语音 codec (FFmpeg / opus / bcg729 / spandsp 等)
- 工具 user guide (.html 文档 18 个)

保留：

- tshark.exe (主程序)
- libwireshark.dll / libwiretap.dll / libwsutil.dll (核心三件套)
- 必要 codec (snappy / zstd / lz4 / bz2 等压缩库，HTTP body 解码可能用到)
- crypto 套件 (gnutls / gcrypt / ssh — TLS 解密 + SSH 协议解析)
- GLib 系 (glib-2.0 / gmodule / gthread / intl / libffi / libwinpthread)
- 其他 (lua54 — tshark 自带 Lua 脚本; libxml2 — XML 协议解析)

## 用法

`analyze.py` 默认从 `tools/src/extend-tools/tshark/tshark.exe` 找 tshark。
也可 `--tshark <path>` 显式指定其它位置。

## 跨平台

**当前子集是 Windows x64 专用**（`tshark.exe` + Windows DLL）。

要在 Linux / macOS 上跑，需要：
1. 从 Wireshark 官网下载对应平台的安装包
2. 用同样的瘦身策略砍到 ~50MB（Linux/macOS 共享库体积更小）
3. 放到 `extend-tools/tshark/` 对应子目录（如 `extend-tools/tshark-linux-x64/`）

`analyze.py` 的 `find_tshark()` 支持通过 `--tshark` 显式指定路径跨平台切换。

## 许可证

Wireshark 是 GPLv2+。保留 `COPYING.txt` 和 `README.txt` 以满足许可证要求。
再分发需遵守 GPL 条款。