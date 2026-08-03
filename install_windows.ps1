[CmdletBinding()]
param(
    [switch]$SkipFrontend
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host "[1/4] Python 3.12 확인" -ForegroundColor Cyan
try {
    & py -3.12 --version
} catch {
    throw "Python 3.12가 필요합니다. https://www.python.org/downloads/windows/ 에서 설치하고 'py launcher'를 활성화하세요."
}

if (-not (Test-Path ".venv")) {
    & py -3.12 -m venv .venv
}

Write-Host "[2/4] 백엔드 의존성 설치" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"

if (-not $SkipFrontend) {
    Write-Host "[3/4] 프론트엔드 설치와 빌드" -ForegroundColor Cyan
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        throw "Node.js LTS가 필요합니다. 'winget install OpenJS.NodeJS.LTS' 후 다시 실행하세요."
    }
    Push-Location frontend
    try {
        & npm ci
        & npm run build
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[3/4] 프론트엔드 설치 생략" -ForegroundColor Yellow
}

Write-Host "[4/4] 로컬 설정 파일 준비" -ForegroundColor Cyan
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
}
if (-not (Test-Path "config.yaml")) {
    Copy-Item "config.example.yaml" "config.yaml"
}

Write-Host ""
Write-Host "설치 완료. run_windows.ps1 또는 run_windows.bat을 실행하세요." -ForegroundColor Green
Write-Host "추가 OSS 도구는 install_oss_tools.ps1에서 명시적으로 선택해 설치할 수 있습니다."
