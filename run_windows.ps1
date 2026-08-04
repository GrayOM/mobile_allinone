[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [switch]$LanAccess,
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
$LoopbackHosts = @("127.0.0.1", "localhost", "::1")
if ($HostAddress -in @("0.0.0.0", "::", "*")) {
    throw "0.0.0.0/:: wildcard 바인딩은 허용하지 않습니다. 특정 Windows LAN IP를 지정하세요."
}
if ($HostAddress -notin $LoopbackHosts -and -not $LanAccess) {
    throw "loopback 외 주소는 -LanAccess를 명시해야 합니다."
}

function New-MswToken {
    $Bytes = New-Object byte[] 32
    $Generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $Generator.GetBytes($Bytes) } finally { $Generator.Dispose() }
    return [Convert]::ToBase64String($Bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

if ($LanAccess) {
    $env:MSW_LAN_ACCESS = "true"
    if (-not $env:MSW_API_TOKEN) { $env:MSW_API_TOKEN = New-MswToken }
    if (-not $env:MSW_ADMIN_TOKEN) { $env:MSW_ADMIN_TOKEN = New-MswToken }
    $env:MSW_TRUSTED_HOSTS = $HostAddress
    Set-Clipboard -Value ($env:MSW_API_TOKEN + "|" + $env:MSW_ADMIN_TOKEN)
    Write-Host "LAN 세션용 임시 인증 문자열을 클립보드에 복사했습니다. 브라우저 잠금 화면에 붙여넣으세요." -ForegroundColor Yellow
}
$env:MSW_HOST = $HostAddress
$env:MSW_PORT = "$Port"
$Url = "http://${HostAddress}:${Port}/"

Write-Host "Mobile Security Workbench 시작: $Url" -ForegroundColor Green
Write-Host "종료하려면 이 창에서 Ctrl+C를 누르세요." -ForegroundColor DarkGray
if (-not $NoBrowser) {
    Start-Process $Url
}

& $Python -m uvicorn backend.app.main:app --host $HostAddress --port $Port
