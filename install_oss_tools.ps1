[CmdletBinding()]
param(
    [switch]$All,
    [switch]$Frida,
    [switch]$Mitmproxy,
    [switch]$Semgrep,
    [switch]$APKiD,
    [switch]$Objection,
    [switch]$Pymobiledevice3,
    [switch]$Drozer,
    [switch]$AcceptCopyleftLicenses
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw ".venv가 없습니다. 먼저 install_windows.ps1을 실행하세요."
}

if ($All) {
    $Frida = $true
    $Mitmproxy = $true
    $Semgrep = $true
    $APKiD = $true
    $Objection = $true
    $Pymobiledevice3 = $true
    $Drozer = $true
}

function Install-PythonTool {
    param([string]$Name, [string]$Package)
    Write-Host "[$Name] 설치 시도" -ForegroundColor Cyan
    & $Python -m pip install --upgrade $Package
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[$Name] 설치 실패 — 플랫폼 지원과 빌드 의존성을 확인하세요." -ForegroundColor Yellow
        return
    }
    Write-Host "[$Name] 설치 완료" -ForegroundColor Green
}

if ($Frida) { Install-PythonTool "Frida" "frida-tools" }
if ($Mitmproxy) { Install-PythonTool "mitmproxy" "mitmproxy" }
if ($Semgrep) { Install-PythonTool "Semgrep" "semgrep" }

$CopyleftSelected = $APKiD -or $Objection -or $Pymobiledevice3 -or $Drozer
if ($CopyleftSelected -and -not $AcceptCopyleftLicenses) {
    Write-Host ""
    Write-Host "APKiD/objection/pymobiledevice3/drozer는 별도 오픈소스 라이선스 조건이 있습니다." -ForegroundColor Yellow
    Write-Host "docs\OSS_INTEGRATIONS.md와 각 프로젝트 라이선스를 검토한 뒤 -AcceptCopyleftLicenses를 추가하세요."
    $APKiD = $false
    $Objection = $false
    $Pymobiledevice3 = $false
    $Drozer = $false
}

if ($APKiD) { Install-PythonTool "APKiD" "apkid" }
if ($Objection) { Install-PythonTool "objection" "objection" }
if ($Pymobiledevice3) { Install-PythonTool "pymobiledevice3" "pymobiledevice3" }
if ($Drozer) {
    if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
        Write-Host "[drozer] pipx가 없어 설치하지 않았습니다. 'py -m pip install pipx' 후 다시 실행하세요." -ForegroundColor Yellow
    } else {
        & pipx install drozer
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[drozer] 설치 실패 — pipx 출력과 Python 버전을 확인하세요." -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "MobSF는 이 스크립트가 자동 설치하지 않습니다. 별도 Docker 인스턴스의 URL/API 키를 .env에 설정하세요."
Write-Host "jadx, apktool, Android SDK, libimobiledevice는 공식 배포본 경로를 설정 화면에서 지정하세요."
Write-Host "도구별 최종 상태는 서버 재시작 후 설정 > 연결된 오픈소스 기능에서 확인하세요." -ForegroundColor Green
