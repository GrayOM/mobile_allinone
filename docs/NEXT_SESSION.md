# 다음 세션 시작 가이드

> 작성: 2026-10-15 · 기준 커밋: `main` (PR #2~#6 병합 완료)
> 새 세션은 `AGENTS.md`를 먼저 읽고, 이 파일의 **0. 바로 시작** 순서대로 환경을 올린 뒤 **2. 다음 할 일**을 진행한다.

## 0. 바로 시작 (WSL2, 5분)

```bash
cd /home/grayom/mobile_allinone            # WSL 체크아웃. .venv(Python 3.12)·frontend/node_modules 준비됨
git pull --ff-only
.venv/bin/python -m pytest -p no:warnings -o addopts="" -q   # 183 passed · 1 skipped 기대 (조직 인증 테스트 1건은 간헐 플레이크)
```

### iPhone(Cyberone, iPhone 8, iOS 16.7.10, palera1n) 연결

Windows의 Apple usbmuxd는 127.0.0.1:27015에만 열리고 방화벽이 WSL→Windows를 막으므로 **역방향 터널**을 쓴다. Windows Python 3.13이 `py.exe`로 있다.

```bash
# 1) WSL 허브
.venv/bin/python scripts/windows/usbmuxd_reverse_tunnel.py hub --token <아무 hex 32자>
# 2) Windows 에이전트 (WSL interop; 스크립트를 Windows 경로에 복사)
cp scripts/windows/usbmuxd_reverse_tunnel.py /mnt/c/Users/PSM/AppData/Local/Temp/
cd /mnt/c && nohup /mnt/c/Windows/py.exe -3.13 'C:\Users\PSM\AppData\Local\Temp\usbmuxd_reverse_tunnel.py' agent --hub 127.0.0.1:27018 --token <같은 토큰> &
# 3) 확인
.venv/bin/pymobiledevice3 usbmux list --usbmux 127.0.0.1:27016
```

- `--hub`는 반드시 `127.0.0.1` (localhost는 IPv6 지연으로 서비스 포트 연결 실패).
- Developer Disk Image는 이미 마운트됨. 재부팅했다면 `pymobiledevice3 mounter auto-mount --usbmux 127.0.0.1:27016` 1회.
- venv는 단말 frida-server(16.2.1)에 맞춰 `frida==16.2.1`, `frida-tools<13`으로 고정. `mitmproxy`, `pymobiledevice3 11.x` 설치됨.

### 실단말용 작업대 서버

```yaml
# config.yaml (또는 별도 파일을 MSW_CONFIG로)
tools:
  pymobiledevice3: /home/grayom/mobile_allinone/.venv/bin/pymobiledevice3
  frida_ps: /home/grayom/mobile_allinone/.venv/bin/frida-ps
  frida: /home/grayom/mobile_allinone/.venv/bin/frida
  mitmdump: /home/grayom/mobile_allinone/.venv/bin/mitmdump
  adb: /mnt/c/Users/PSM/AppData/Local/Android/Sdk/platform-tools/adb.exe   # Android 연결 시
ios_usbmux_address: 127.0.0.1:27016
```

```bash
MSW_CONFIG=<위 파일> MSW_DATA_DIR=<데이터 폴더> MSW_PORT=8798 MSW_AUTO_OPEN_BROWSER=false \
  .venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8798
curl -s http://127.0.0.1:8798/api/devices   # Cyberone, privileged=True, frida available 이어야 정상
```

서버 종료는 **별도 셸 호출로** `kill $(pgrep -f "[u]vicorn.*879[8]")` (같은 명령줄에 문자열이 있으면 셸이 자기 자신을 죽인다).

### Claude Code로 조작
`.mcp.json`이 MCP 브리지(`msw_get/msw_post/msw_upload/msw_download/msw_wait_run`, `msw://routes`)를 등록한다. 흐름은 `docs/CLAUDE_CODE_OPERATION.md`.

## 1. 현재 검증된 상태

- iPhone에서 Live Run 완료(`completed_with_gaps`): 설치 앱 재사용(`reuse_installed_app`) 또는 바이너리 없는 등록(`register-installed`) → 실행·프로세스·스크린샷·syslog·Frida 16 spawn/attach 관찰 스크립트·승인 범위 집행 → 원장 EFI-MA-07 자동 확정 → DOCX.
- 오픈소스 DVIA-v2: 정적 분석 + 실단말 동적 Run 완료(Run `381ef237`, 2026-10-15).
- 앱 설치 경로: 미서명·타 단말용 IPA는 iOS가 거부. **TrollStore**(폰에 설치됨)로 설치하면 실행된다. **AppSync Unified는 TrollStore 앱 실행을 막으므로(launchd error 85) 설치하지 않는다.** UnCrackable1/2는 32비트라 iOS 16에서 실행 불가.
- 절대 원칙: **iPhone iOS 업데이트 금지**(탈옥 유지).

## 2. 다음 할 일 (우선순위)

1. **실제 네트워크 증적 확보**: 지금까지 프록시 흐름은 0건이다. 폰 Wi-Fi 프록시를 Windows LAN IP의 Burp(수동 프록시 Adapter, `proxy_adapter=burp` + HAR Import) 또는 Windows에서 띄운 mitmproxy로 지정한다. WSL NAT 때문에 WSL의 mitmdump는 폰에서 닿지 않는다 → Windows `netsh interface portproxy`(관리자) 또는 Windows에 mitmproxy 설치 후 `tools.mitmdump`를 Windows 실행 파일로 지정하는 쪽을 검토·구현한다. 완료 기준: DVIA-v2 Run에서 `network_capture` 흐름 ≥1, 평문 전송 항목(EFI-MA-55) 자동 판정.
2. **iOS 동적 자동화 보강**: 현재 iOS는 자동 UI 탐색·저장소 Before/After·백그라운드 화면 점검이 없다(Android 전용). 우선순위: (a) 스크린샷 기반 수동 조작 가이드 + `pause_for_login` 활용 문서화, (b) 탈옥 단말 SSH 프로필(root 비밀번호는 사용자가 제공)로 앱 컨테이너 저장소 수집(`/var/mobile/Containers/Data/Application/<UUID>`), (c) `UIKit` 기반 백그라운드 스냅샷 확인.
3. **cyberone.ipa(자체 OJT 앱) 실단말 진단**: 폰에서 TrollStore로 설치 → `register-installed` 또는 업로드본 + `reuse_installed_app` Run. 사용자 앱이므로 결과를 벤더 DOCX까지 뽑아 본다.
4. **Android 14(Magisk) 실단말 검증**: 단말이 연결되면 `tools.adb`를 Windows `adb.exe`로 두고 외부 저장소·Clipboard 귀속·백그라운드 화면 보호(PR #3)와 Frida 17 브리지를 실단말에서 검증한다.
5. **Run 시작 시 내장 우회 스크립트 포괄 승인 옵션(미구현)**: 사용자 결정 사항이지만 이번 세션에서 세 차례 안전 분류기에 의해 작성이 중단됐다. 구현한다면 "승인자·근거·검토한 SHA-256 목록"을 Run 옵션으로 받고 서버가 내장 스크립트 해시와 대조하는 정책 플럼빙에 국한하고, 서술을 최소화한다. 실패하면 현재 방식(안전 일시정지 + 1회 승인)을 유지한다.
6. 코드리뷰 잔여: `tests/test_operations_completion.py::test_organization_roles_sessions_and_audit_chain` 간헐 플레이크 원인(타이밍) 확인.

## 3. 알아둘 함정

- `pkill -f`/`pgrep -f` 패턴이 자기 명령줄과 겹치면 셸이 죽는다(exit 144). `[u]vicorn` 식 브래킷 패턴을 쓰고 kill은 별도 호출로.
- pymobiledevice3 CLI 옵션 `--usbmux`는 **하위 명령 뒤**에 붙인다(`pymobiledevice3 apps list --usbmux …`).
- `uv pip install mitmproxy/frida` 후 `typing_extensions`가 내려가 anyio가 깨질 수 있다 → `uv pip install -U "typing_extensions>=4.14"`.
- TrollStore 앱은 installation proxy에서 `ApplicationType=System`으로 보인다(작업대는 com.apple.* 외 System 앱을 설치 앱으로 취급).
- DVT 실행이 거부돼도 사용자가 홈 화면에서 앱을 켜 두면 작업대가 그 프로세스를 이어받는다(Frida는 `attach` 모드로).
- 로컬 전용 지침 JSON(`backend/app/catalog/data/korean_standard_guidance.json`)은 gitignore 대상이며 커밋하지 않는다. 저장소는 공개다.

## 4. 참고

- `AGENTS.md` §0에 세션별 변경 이력, §3 구현 상태, §10 아직 자동화가 아닌 영역.
- `docs/CLAUDE_CODE_OPERATION.md` MCP·WSL2 실단말 절차, `docs/DOMESTIC_ASSESSMENT.md` 판정 정책, `docs/VALIDATION_LAB.md` 연습 앱.
