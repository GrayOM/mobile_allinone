[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw ".venv가 없습니다. 먼저 install_windows.ps1을 실행하세요."
}
if (-not (Test-Path "frontend\dist\index.html")) {
    throw "프론트엔드 빌드가 없습니다. install_windows.ps1을 다시 실행하거나 frontend에서 npm run build를 실행하세요."
}

$env:PYTHONPATH = $ProjectRoot
$env:MSW_HOST = $HostAddress
$env:MSW_PORT = "$Port"
$Url = "http://${HostAddress}:${Port}"

Write-Host "Mobile Security Workbench 시작: $Url" -ForegroundColor Green
Write-Host "종료하려면 이 창에서 Ctrl+C를 누르세요." -ForegroundColor DarkGray
if (-not $NoBrowser) {
    Start-Process $Url
}

& $Python -m uvicorn backend.app.main:app --host $HostAddress --port $Port

