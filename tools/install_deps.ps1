# tools/install_deps.ps1
# 一键安装 v0.2.0 依赖
# 使用: powershell -ExecutionPolicy Bypass -File tools\install_deps.ps1

$ErrorActionPreference = "Stop"

Write-Host "[1/2] 检查 Python..." -ForegroundColor Cyan
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "[错误] 未找到 python，请先安装 Python 3.10+" -ForegroundColor Red
    exit 1
}
$ver = & python --version
Write-Host "  $ver"

Write-Host "[2/2] pip install -r tools/requirements.txt ..." -ForegroundColor Cyan
& python -m pip install -r "$PSScriptRoot\requirements.txt"

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[完成] 依赖装好了，试试:" -ForegroundColor Green
    Write-Host "  python tools\src\mvp_v3.py --pcap <your.pcap>" -ForegroundColor Yellow
} else {
    Write-Host "[失败] pip 安装出错，查看上面日志" -ForegroundColor Red
    exit 1
}