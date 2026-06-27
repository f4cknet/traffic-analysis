#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
初始化仓库 + 首次提交 + 推送
按铁律: 文档优先, 每次变更单独 commit
"""
import subprocess
import sys
from pathlib import Path

REPO  = Path(r"D:\ctf\analyzer-toolkit")
GIT   = "git"
EMAIL = "zmzsg100@gmail.com"
USER  = "f4cknet"

def run(cmd, cwd=None, check=True):
    r = subprocess.run(cmd, cwd=str(cwd or REPO), capture_output=True, text=True)
    if r.stdout: print(r.stdout.strip())
    if r.stderr: print(r.stderr.strip())
    if check and r.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}")
        sys.exit(1)
    return r

# 1. git init
print("=" * 60)
print("1. git init")
print("=" * 60)
run([GIT, "init"])
run([GIT, "init", "-b", "main"])

# 2. 配置 user (仓库级别, 不污染全局)
print("\n" + "=" * 60)
print("2. 配置 git user")
print("=" * 60)
run([GIT, "config", "user.name",  USER])
run([GIT, "config", "user.email", EMAIL])

# 3. 显示待提交内容
print("\n" + "=" * 60)
print("3. 待提交文件")
print("=" * 60)
run([GIT, "status", "--short"])

# 4. add
print("\n" + "=" * 60)
print("4. git add")
print("=" * 60)
run([GIT, "add", "."])
run([GIT, "status", "--short"])

# 5. commit
print("\n" + "=" * 60)
print("5. git commit (v0.1.0)")
print("=" * 60)
commit_msg = """docs: initial project skeleton (v0.1.0)

- README.md: project entry point
- docs/REQUIREMENTS.md: problem types and answer formats
- docs/ARCHITECTURE.md: tool architecture and data flow
- docs/ROADMAP.md: iteration plan v0.1.0 -> v1.0.0
- docs/CHANGELOG.md: version history
- docs/evidence-rules.md: scanner identification levels
- .gitignore: exclude pcap/log/debug files
- tools/generate_ssh_key.py: dev utility for SSH key generation

Following 'doc-first, implement-later' iron rule.
No core analysis code in v0.1.0 -- that lands in v0.2.0.
"""
run([GIT, "commit", "-m", commit_msg])
run([GIT, "log", "--oneline"])

# 6. remote
print("\n" + "=" * 60)
print("6. git remote add + push")
print("=" * 60)
remote_url = "git@github.com:f4cknet/traffic-analysis.git"
# 检查是否已存在 remote
r = run([GIT, "remote", "-v"], check=False)
if "f4cknet/traffic-analysis" not in r.stdout:
    run([GIT, "remote", "add", "origin", remote_url])
run([GIT, "remote", "-v"])

print("\n" + "=" * 60)
print("7. git push -u origin main")
print("=" * 60)
run([GIT, "push", "-u", "origin", "main"])

print("\n" + "=" * 60)
print("Done. v0.1.0 已推送到 GitHub")
print("=" * 60)
