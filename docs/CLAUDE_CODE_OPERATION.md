# Claude Code로 작업대 조작하기

Claude Code 세션이 MCP로 로컬 작업대를 조작하는 방법과, WSL2에서 실제 Android 14·iOS 16.7.10 단말을 연결하는 절차를 정리한다. 작업대의 안전 경계(승인 토큰, Run 상태 검사, 승인 범위 검증)는 모두 서버에 남아 있으며 MCP 브리지는 REST API를 그대로 전달하는 얇은 클라이언트다.

## 1. 구성

1. 작업대 서버를 먼저 띄운다. WSL/Linux는 `scripts/run.sh`, Windows는 `run_windows.ps1`. 기본 주소는 `http://127.0.0.1:8765`.
2. MCP 의존성은 선택 extra다: `pip install -e ".[mcp]"` (dev extra에도 포함). 저장소 루트의 `.mcp.json`이 `mobile-security-workbench` 서버를 등록한다. 기본 `command`는 WSL/Linux/macOS의 `.venv/bin/python`이며 Windows에서는 `.venv\\Scripts\\python.exe`로 바꾸거나 `claude mcp add mobile-security-workbench -- .venv\\Scripts\\python.exe -m backend.app.mcp_server`로 사용자 범위에 등록한다. Claude Code를 저장소 루트에서 실행하면 자동으로 로드된다. 서버 주소가 다르면 `MSW_BASE_URL`, LAN 토큰 모드이면 `MSW_API_TOKEN`을 `env`에 추가한다.
3. 세션에서 `msw://routes` 리소스를 먼저 읽고 다음 도구를 쓴다.

| 도구 | 용도 |
|---|---|
| `msw_get(path, params)` | 조회 (`/api/devices`, `/api/runs/{id}`, `/api/coverage?run_id=…`) |
| `msw_post(path, body, method)` | 생성·상태 변경 (`/api/runs`, `/api/approvals`, `/api/runs/{id}/resume`, PATCH/PUT/DELETE 포함) |
| `msw_upload(path, file_path)` | APK/IPA 업로드, HAR 가져오기, 판정 증적 첨부(`/assessment-controls/{id}/evidence`, `/findings/{id}/evidence`) |
| `msw_download(evidence_id, dir)` | 화면·원본·보고서를 로컬 파일로 받는다. Claude Code는 받은 PNG를 Read로 직접 본다 |
| `msw_wait_run(run_id, timeout)` | Run이 안전 일시정지 또는 종료될 때까지 대기 |

## 2. 권장 진단 흐름

```text
프로젝트 생성 → 앱 업로드(정적 분석 자동) → /apps/{id}/analysis/overview 로 보안통제 신호 확인
→ 단말 확인(/devices) → Run 시작(pause_for_login, pause_for_security_bypass 등 옵션)
→ msw_wait_run 으로 safely_paused 대기 → 필요한 수동 작업·승인(/approvals → 실행 API)
→ resume → 종료 후 /coverage?run_id=…&scope=run 원장 검토 → 증적 다운로드·판정 기록
→ 취약 확정 항목만 /runs/{id}/report/docx 로 DOCX 생성
```

- 고위험 작업(우회 스크립트 Spawn, 중위험 UI 동작, Live GET/HEAD 재현, 컴포넌트 호출)은 `safely_paused` 상태에서 `/api/approvals`로 5분 만료 1회 토큰을 받은 뒤 실행 API에 넘긴다. 승인 요청 전에 Claude Code는 대상·코드 SHA-256·범위를 사용자에게 보여 주고 확인을 받는다.
- ALL 프로필에서는 `POST /api/findings`로 Run에 묶인 발견항목을 만들고, 단말에서 직접 찍은 화면은 `POST /api/findings/{id}/evidence`로 첨부한 뒤 `POST /api/findings/{id}/record`로 확정한다. 국내 기준 항목에서 만든 발견항목은 이 경로로 판정할 수 없다(409).
- 판정은 `/api/assessment-controls/{id}/record`로 남긴다. `confirmed`는 같은 Run의 필수 증적 ID가 있어야 하며 정적 신호나 AI 추천만으로는 422로 거부된다.
- NVIDIA 추천(`/apps/{id}/ai/triage`, `/runs/{id}/ai/evidence-priority`)은 `needs_review` 후보일 뿐이다. 최종 판정은 Claude Code가 증적을 직접 확인한 뒤 사용자와 함께 기록한다.

## 3. WSL2에서 실단말 연결

### Android 14 (Magisk)

- Windows에 Platform-Tools를 설치하고 `adb.exe`로 단말을 먼저 인식시킨다(USB 디버깅 허용).
- WSL 쪽 `adb`는 Windows adb 서버를 공유한다. `.env` 또는 `config.yaml`의 `adb` 경로를 Windows 바이너리(`/mnt/c/.../platform-tools/adb.exe`)로 지정하면 가장 단순하다. `adb.exe`는 WSL에서 실행 가능하며 같은 서버·단말 목록을 쓴다.
- Frida: 단말의 `frida-server`는 Magisk 모듈 또는 수동 push로 실행한다. Python `frida`가 USB 장치를 보려면 `usbipd-win`으로 USB를 WSL에 attach하거나, `adb forward tcp:27042 tcp:27042` 뒤 `127.0.0.1:27042` 원격 장치를 쓴다.
- Root tar 수집·외부 저장소·Task 스냅샷 읽기는 Magisk `su`가 있으면 그대로 동작한다.

### iOS 16.7.10 (palera1n)

- palera1n은 Linux/macOS에서 실행하므로 탈옥 자체는 WSL이 아니라 별도 Linux 부팅 또는 macOS에서 수행한다. 탈옥 후 OpenSSH와 Frida(Sileo/Zebra)를 설치한다.
- WSL에서 `usbipd-win`으로 단말을 attach하고 `usbmuxd`를 띄우면 libimobiledevice·pymobiledevice3가 USB를 인식한다. 간단한 대안은 Wi-Fi SSH 프로필이다. `/api/devices/ios/profiles`에 host·username·`frida_endpoint`(예: `127.0.0.1:27042`를 `iproxy`로 포워딩)를 등록한다.
- IPA 설치·재서명은 zsign으로 하고 실제 서명 자료는 `.env`에서만 읽는다.

## 4. 아직 실단말에서 검증되지 않은 것

- `dumpsys clipboard`·`dumpsys window` 출력 형식(Android 14 실제 값), Task 스냅샷 파일 위치
- Frida 17 브리지 번들의 실단말 로드
- iOS 자동 탐색·저장소·백그라운드 점검(현재 Android 전용)

실단말에서 처음 실행할 때는 `run_mode=live` 프로젝트와 승인 통제 검증 범위(`control_validation`)를 반드시 입력하고, 실패한 단계는 `completed_with_gaps`/`manual_required`로 남는지 확인한다.
