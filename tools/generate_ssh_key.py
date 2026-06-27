#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
生成 ed25519 SSH key (空密码, GitHub 推荐)
- 邮箱: zmzsg100@gmail.com
- 路径: HOME/.ssh/id_ed25519
- 绕过 PowerShell 调 native command 的引号/参数解析坑
"""
import os
import subprocess
import sys
from pathlib import Path

KEY_DIR  = Path(r"C:\Users\zmzsg\.ssh")
KEY_PATH = KEY_DIR / "id_ed25519"
KEYGEN   = Path(r"C:\Windows\System32\OpenSSH\ssh-keygen.exe")
EMAIL    = "zmzsg100@gmail.com"

KEY_DIR.mkdir(parents=True, exist_ok=True)

if KEY_PATH.exists():
    print(f"Key already exists: {KEY_PATH}")
    print(f"  (comment: {KEY_PATH.with_suffix('.pub').read_text().strip().split()[-1]})")
    print("")
    print("=" * 60)
    print("Public Key (复制到 GitHub):")
    print("=" * 60)
    print((KEY_PATH.with_suffix(".pub")).read_text().strip())
    sys.exit(0)

temp_pass = "temp_pass_1234"

# Step 1: 用临时密码生成
print(f"Step 1: 生成 ed25519 key (comment: {EMAIL})...")
r = subprocess.run(
    [str(KEYGEN), "-t", "ed25519",
     "-C", EMAIL,
     "-f", str(KEY_PATH),
     "-N", temp_pass],
    capture_output=True, text=True,
)
if r.returncode != 0 or not KEY_PATH.exists():
    print(f"Step 1 失败: {r.stderr or r.stdout}")
    sys.exit(1)
print("  Step 1 OK")

# Step 2: 改成空密码
print("Step 2: 改密码为空...")
r = subprocess.run(
    [str(KEYGEN), "-p",
     "-P", temp_pass,
     "-N", "",
     "-f", str(KEY_PATH)],
    capture_output=True, text=True,
)
if r.returncode != 0:
    print(f"Step 2 失败: {r.stderr or r.stdout}")
    sys.exit(1)
print("  Step 2 OK")

# Step 3: 启动 ssh-agent 并添加 key (Windows OpenSSH)
print("Step 3: 启动 ssh-agent ...")
r = subprocess.run(["powershell", "-NoProfile", "-Command",
                    "Start-Service ssh-agent; Set-Service ssh-agent -StartupType 'Automatic'"],
                   capture_output=True, text=True)
print(f"  {r.stdout.strip() or r.stderr.strip() or 'OK'}")

print("Step 4: ssh-add ...")
r = subprocess.run(["ssh-add", str(KEY_PATH)],
                   capture_output=True, text=True)
print(f"  {r.stdout.strip() or r.stderr.strip() or 'OK'}")

# Step 5: 显示结果
print("")
print("=" * 60)
print("Public Key (复制到 GitHub):")
print("=" * 60)
print((KEY_PATH.with_suffix(".pub")).read_text().strip())

print("")
print("=" * 60)
print("Fingerprint:")
print("=" * 60)
r = subprocess.run([str(KEYGEN), "-l", "-f", str(KEY_PATH)],
                   capture_output=True, text=True)
print(r.stdout.strip())

print("")
print("=" * 60)
print("文件位置:")
print("=" * 60)
for p in KEY_DIR.iterdir():
    print(f"  {p.name}  ({p.stat().st_size} bytes)")
