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
→ 단말 확인(/devices) → Run 시작(interactive_session, pause_for_security_bypass 등 옵션)
→ msw_wait_run 으로 safely_paused 대기 → 앱을 직접 재현하고 /runs/{id}/checkpoints를 필요한 만큼 반복
→ 필요한 승인 작업(/approvals → 실행 API)
→ resume → 종료 후 /coverage?run_id=…&scope=run 원장 검토 → 증적 다운로드·판정 기록
→ 취약 확정 항목만 /runs/{id}/report/docx 로 DOCX 생성
```

- 고위험 작업(우회 스크립트 Spawn, 중위험 UI 동작, Live GET/HEAD 재현, 컴포넌트 호출)은 `safely_paused` 상태에서 `/api/approvals`로 5분 만료 1회 토큰을 받은 뒤 실행 API에 넘긴다. 승인 요청 전에 Claude Code는 대상·코드 SHA-256·범위를 사용자에게 보여 주고 확인을 받는다.
- iOS 설치본을 재사용하는 단말 진단은 `proxy_adapter=none`, `options.reuse_installed_app=true`, `interactive_session=true`, `network_capture_required=false`로 시작할 수 있다. 이 모드는 네트워크 검증을 성공한 것으로 위장하지 않고 Run 범위에서 명시적으로 제외한다. 설치본의 Bundle ID와 버전을 대조하며 버전이 다르면 별도 허용 없이는 중단한다.
- 대화형 Session은 `safely_paused`의 `manual_interaction` 단계에서 `POST /api/runs/{id}/checkpoints`에 `label`, `note`, `control_ids`를 보내 화면·대상 프로세스·단말 로그·현재 Frida 상태를 하나의 체크포인트로 고정한다. 여러 번 호출할 수 있고, 재개 후에도 Run 원장에 보존된다.
- Run의 `completed`는 선택한 증적 수집 범위가 완료됐다는 뜻이다. 국내 기준 전체 판정은 `options.assessment_status`와 `assessment_open_items`로 별도 표시하며, 한 Run에서 전 항목 판정까지 강제할 때만 `assessment_completion_required=true`를 쓴다.
- ALL 프로필에서는 `POST /api/findings`로 Run에 묶인 발견항목을 만들고, 단말에서 직접 찍은 화면은 `POST /api/findings/{id}/evidence`로 첨부한 뒤 `POST /api/findings/{id}/record`로 확정한다. 국내 기준 항목에서 만든 발견항목은 이 경로로 판정할 수 없다(409).
- 판정은 `/api/assessment-controls/{id}/record`로 남긴다. `confirmed`는 같은 Run의 필수 증적 ID가 있어야 하며 정적 신호나 AI 추천만으로는 422로 거부된다.
- NVIDIA 추천(`/apps/{id}/ai/triage`, `/runs/{id}/ai/evidence-priority`)은 `needs_review` 후보일 뿐이다. 최종 판정은 Claude Code가 증적을 직접 확인한 뒤 사용자와 함께 기록한다.

## 3. WSL2에서 실단말 연결

### Android 14 (Magisk)

- Windows에 Platform-Tools를 설치하고 `adb.exe`로 단말을 먼저 인식시킨다(USB 디버깅 허용). 이 PC에서는 `C:\Users\PSM\AppData\Local\Android\Sdk\platform-tools\adb.exe`(1.0.41, 36.0.2)가 WSL interop으로 바로 실행되는 것을 확인했다(2026-10-14, 단말 미연결 상태).
- WSL 쪽 `adb`는 Windows adb 서버를 공유한다. `config.yaml`의 `tools.adb`를 `/mnt/c/Users/<user>/AppData/Local/Android/Sdk/platform-tools/adb.exe`로 지정하면 WSL 작업대가 Windows의 USB 단말을 그대로 본다. Linux 네이티브 adb를 쓰려면 `usbipd-win`으로 USB를 attach해야 한다(관리자 권한 필요).
- Frida: 단말의 `frida-server`는 Magisk 모듈 또는 수동 push로 실행한다. Python `frida`가 USB 장치를 보려면 `usbipd-win`으로 USB를 WSL에 attach하거나, `adb forward tcp:27042 tcp:27042` 뒤 `127.0.0.1:27042` 원격 장치를 쓴다.
- Root tar 수집·외부 저장소·Task 스냅샷 읽기는 Magisk `su`가 있으면 그대로 동작한다.

### iOS 16.7.10 (palera1n) — 검증 완료 경로

Apple Mobile Device Service(usbmuxd)는 Windows의 127.0.0.1:27015에만 열려 있고 Windows 방화벽이 WSL→Windows 연결을 막는다. 반대로 Windows→WSL 연결은 허용되므로 **역방향 터널**로 usbmuxd를 WSL에 노출한다. 2026-10-14 iPhone 8(iOS 16.7.10, palera1n)에서 아래 순서로 단말 인식·앱 목록·DVT 프로세스·앱 실행·종료·스크린샷·syslog·Frida 16 연결까지 확인했다.

```bash
# 1) WSL: 허브 (loopback 27016 = usbmuxd 클라이언트용, 27018 = Windows agent용)
.venv/bin/python scripts/windows/usbmuxd_reverse_tunnel.py hub --token <랜덤토큰>
# 2) Windows Python(3.13)으로 agent 실행 (WSL에서 interop으로 띄워도 된다)
py -3.13 \\wsl$\Ubuntu\home\...\scripts\windows\usbmuxd_reverse_tunnel.py agent --hub 127.0.0.1:27018 --token <같은토큰>
# 3) WSL 확인
pymobiledevice3 usbmux list --usbmux 127.0.0.1:27016
pymobiledevice3 mounter auto-mount --usbmux 127.0.0.1:27016   # DVT(스크린샷·프로세스·실행)용 Developer Disk Image, 1회
```

작업대 설정(`config.yaml` 또는 `.env`):

```yaml
ios_usbmux_address: 127.0.0.1:27016      # MSW_IOS_USBMUX_ADDRESS
ios_frida_forward_port: 27042            # MSW_IOS_FRIDA_FORWARD_PORT
tools:
  pymobiledevice3: /path/.venv/bin/pymobiledevice3
  frida_ps: /path/.venv/bin/frida-ps
```

- 작업대는 모든 pymobiledevice3 호출에 `USBMUXD_SOCKET_ADDRESS`를 넣고, Frida는 `usbmux forward 27042`를 작업대가 직접 띄워 `127.0.0.1:27042` 원격 대상으로 연결한다(서버 종료 시 정리).
- 단말의 frida-server가 16.x이면 WSL의 `frida`/`frida-tools`도 16.x로 맞춘다(`uv pip install "frida==16.2.1" "frida-tools<13"`). Frida 17 런타임 호환 shim은 16에서도 동작한다.
- agent의 `--hub`는 반드시 `127.0.0.1`을 쓴다. `localhost`는 Windows에서 IPv6를 먼저 시도해 서비스 포트 연결이 수 초 지연되고 iOS가 StartService 포트를 닫아 `Connect` 실패(Result 3)가 난다.
- `privileged`는 frida-server(시스템 데몬)가 응답할 때만 `True`로 표시한다(`jailbreak_signal=frida_server_reachable`). SSH(22)가 열려 있어도 자격 증명은 저장하지 않는다.


- palera1n 탈옥 자체는 Linux/macOS에서 수행한다. 탈옥 후 OpenSSH와 Frida(Sileo/Zebra)를 설치한다. `usbipd-win`으로 USB를 WSL에 직접 붙이는 방법도 있지만 관리자 권한과 커널 usbmuxd가 필요해 위 역방향 터널을 기본 경로로 쓴다.
- IPA 설치·재서명은 zsign으로 하고 실제 서명 자료는 `.env`에서만 읽는다.

## 4. 아직 실단말에서 검증되지 않은 것

- `dumpsys clipboard`·`dumpsys window` 출력 형식(Android 14 실제 값), Task 스냅샷 파일 위치
- Frida 17 브리지 번들의 실단말 로드
- iOS 자동 탐색·저장소·백그라운드 점검(현재 Android 전용)

실단말에서 처음 실행할 때는 `run_mode=live` 프로젝트와 승인 통제 검증 범위(`control_validation`)를 반드시 입력하고, 실패한 단계는 `completed_with_gaps`/`manual_required`로 남는지 확인한다.
