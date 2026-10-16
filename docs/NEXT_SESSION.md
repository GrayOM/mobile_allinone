# 다음 세션 시작 가이드

> 작성: 2026-10-16 · 기준 브랜치: `main`
> 새 세션은 `AGENTS.md`를 먼저 읽고, 이 파일의 **0. 바로 시작** 순서대로 환경을 올린 뒤 **2. 다음 할 일**을 진행한다.

## 0. 바로 시작 (WSL2, 5분)

```bash
cd /home/grayom/mobile_allinone            # WSL 체크아웃. .venv(Python 3.12)·frontend/node_modules 준비됨
git pull --ff-only
MSW_CONFIG=/tmp/msw-test-no-config.yaml .venv/bin/python -m pytest -p no:warnings -o addopts="" -q
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

- 새 프로젝트 기본값은 `domestic_all`이다. CII 27개와 EFI 56개를 같은 앱 기준선·점검 계획·Run 원장에 총 83개 생성하며, 전 항목 종결 전에는 Run 완료와 최종 DOCX를 막는다. 기존 단일 기준 프로젝트와 과거 Run은 자동 변경하지 않는다. Cyberone의 기존 프로젝트는 EFI 전용이므로 83개 전수 재진단은 통합 프로필의 새 프로젝트에서 앱 원본을 등록해 시작해야 한다. 전체 backend 195 passed·1 skipped, frontend build·audit(취약점 0)를 통과했다.
- 고객 DOCX는 Run 원본 전체를 나열하지 않는다. 검토자가 선택한 증적에서 중복 이미지·체크포인트/판정 컨테이너를 제거하고, 화면은 재현 순서대로 보여 주며 기술 원본은 명령·JSON·syslog 덤프 대신 확인 사실과 SHA-256만 표시한다. 판정을 다시 저장하면 현재 선택으로 교체되며 선택 해제한 원본도 Run에서는 삭제되지 않는다.
- iPhone 홈 화면에 지속된 초록색 가로 띠는 iOS 손쉬운 사용 `스위치 제어`의 글라이딩 커서다. 작업대가 만든 화면이 아니며 저장소에도 활성화 코드가 없다. iPhone 8 홈 버튼을 빠르게 세 번 누르거나 `설정 → 손쉬운 사용 → 스위치 제어`에서 끈다.
- Live 국내 기준 Run에는 해제 불가능한 전수 판정 게이트가 적용된다. 자동 수집 후 미점검·추가 검토가 남으면 `assessment_completion`에서 안전 일시정지되며 재개 API도 409로 차단한다. 취약·양호·해당없음 모두 기준 수행 확인과 구체적 사유가 필요하고, 모든 항목이 종결 판정이며 Run의 다른 필수 Gap도 없을 때만 `completed` 및 최종 DOCX가 열린다. 원장 화면 상단에서 남은 항목과 잠금 단계를 먼저 보여준다. 확정 취약점 원장 증적은 전수 판정 완료 시 한 번만 생성한다.
- 가장 최신 Run `a5f47c17-8582-4d0e-8da0-5c7b99422458`은 Cyberone OJT 전체 승인 범위로 시작한 대화형 Live Run이며 `security_bypass_preparation`에서 `safely_paused`(22%)다. v2 우회 Spawn과 체크포인트 2건은 성공했다. 합성 등록 스크립트 2개는 입력 필드/접근성 대상이 0개라 fail-closed로 끝나 데이터 변경이 없었다. 마지막 읽기 전용 런타임 표면 관찰은 완료됐지만 약 95KB 메시지가 제한에 걸려 일부만 보존됐다. 기존 1회 승인은 모두 소비됐고 승인 범위도 다음 세션에는 만료된 것으로 간주해 다시 검증한다. 서버가 재시작되면 DB의 안전 일시정지 상태와 달리 메모리 Frida 세션은 복구되지 않으므로 무조건 현재 세션 상태부터 조회한다.
- Cyberone OJT 최신 Live Run `5fbbcea1-672a-4bd5-95c8-5accccea03bc`: v2 우회 재승인 후 실단말 증적을 수집하고 `completed_with_gaps`로 종료했다. `EFI-MA-07`과 `EFI-MA-11` 2건 확정, `EFI-MA-33` 양호, `EFI-MA-54` 해당없음, `EFI-MA-21` needs_review, 그 외 needs_review 8·not_tested 43이다. 보고서는 `data/reports/5fbbcea1-672a-4bd5-95c8-5accccea03bc-electronic_financial-vulnerabilities.docx`. 앱 종료로 마지막 프로세스·Frida 확인만 Gap이며 메시지 유실은 0이다.
- Cyberone IPA 재분석 `cd6bfa96-c3ca-4391-b7f8-07bd686f6a21`: SQLite.swift local-storage 신호, `users(name, ssn, pin, bio, breg)` 구조, 벤더 미식별 자체 보호 로직을 확인했다. DB는 현재 0행이라 민감정보 평문 저장을 확정하지 않는다.
- 수동 원장 판정의 `needs_review`가 자동 재평가에서 `not_tested`로 되돌아가던 결함을 수정했다. 최신 수동 검토 이력을 Run options에 먼저 기록하고 원장 평가가 이를 보존한다. 최신 검증은 표적 14 tests와 frontend build·audit(취약점 0) 통과. 전체는 193 passed·1 skipped였고 기존 WebSocket 종료 타이밍 테스트가 1회 간헐 실패했으나 단독 재실행은 통과했다.
- Cyberone OJT Run `ffb8c67d-8518-4f1c-b56f-6ebfd2a7c89a`: 승인된 v2 우회 후 앱이 등록 화면까지 유지되어 `EFI-MA-07`이 실제 취약으로 확정됐다. 앱 한정 백업에서 `Documents/db.sqlite3`가 암호화되지 않은 SQLite이고 `users(name, ssn, pin, bio, breg)` 스키마임을 확인했지만 현재 0행이라 `EFI-MA-21`은 미확정이다. 백업 과정에서 iOS가 앱을 종료했으므로 Run은 `manual_interaction` 안전 일시정지, Frida는 `process-terminated`; 같은 스크립트 재실행에도 새 1회 승인이 필요하다.
- iPhone에서 기존 Live Run(`completed_with_gaps`)과 새 대화형 단말 전용 Run(`completed`)을 모두 검증했다. `proxy_adapter=none`은 네트워크를 명시적으로 범위 제외하고, `interactive_session`은 안전 일시정지 중 화면·프로세스·syslog·Frida 상태 체크포인트를 반복 수집한다. 증적 Session 완료와 국내 기준 판정 완료는 별도 상태다.
- 오픈소스 DVIA-v2: 정적 분석 + 실단말 동적 Run 완료(Run `381ef237`, 2026-10-15).
- DVIA-v2 대화형 검증 Run `f770d63a-6e80-4df8-8385-384b0dc53842`: 설치본 Bundle ID·버전 2.0 일치, Frida attach, 체크포인트 연결 증적 4건, `completed`, 품질 Gap 0. `assessment_status=in_progress`, 미판정 55개는 별도 원장에 유지된다.
- 모바일 보안솔루션 분석기는 25개 정적 시그니처와 독립 Tool Run으로 동작한다. DVIA-v2 재분석 `f73ab1c5-6e72-4aaa-830c-04da6cbabb0e`에서는 알려진 제품 지표가 없어 `no_known_signature`였으며, 이는 미적용 판정이 아니다. 제품별 근거는 앱 화면의 `MOBILE DEFENSE FINGERPRINT`에서 확인한다.
- 앱 설치 경로: 미서명·타 단말용 IPA는 iOS가 거부. **TrollStore**(폰에 설치됨)로 설치하면 실행된다. **AppSync Unified는 TrollStore 앱 실행을 막으므로(launchd error 85) 설치하지 않는다.** UnCrackable1/2는 32비트라 iOS 16에서 실행 불가.
- 절대 원칙: **iPhone iOS 업데이트 금지**(탈옥 유지).

## 2. 다음 할 일 (우선순위)

1. **실제 네트워크 증적 확보**: 지금까지 프록시 흐름은 0건이다. 폰 Wi-Fi 프록시를 Windows LAN IP의 Burp(수동 프록시 Adapter, `proxy_adapter=burp` + HAR Import) 또는 Windows에서 띄운 mitmproxy로 지정한다. WSL NAT 때문에 WSL의 mitmdump는 폰에서 닿지 않는다 → Windows `netsh interface portproxy`(관리자) 또는 Windows에 mitmproxy 설치 후 `tools.mitmdump`를 Windows 실행 파일로 지정하는 쪽을 검토·구현한다. 완료 기준: DVIA-v2 Run에서 `network_capture` 흐름 ≥1, 평문 전송 항목(EFI-MA-55) 자동 판정.
2. **iOS 동적 자동화 보강**: 반복 체크포인트 기반 수동 조작은 구현·실단말 검증됐다. 아직 자동화되지 않은 것은 (a) 탈옥 단말 SSH 프로필(root 비밀번호는 사용자가 제공) 기반 앱 컨테이너 저장소 Before/After, (b) Keychain 구조화 수집, (c) `UIKit` 기반 백그라운드 스냅샷 확인이다.
3. **Cyberone OJT 나머지 실단말 진단**: Run `a5f47c17-8582-4d0e-8da0-5c7b99422458`의 DB 상태·단말 프로세스·메모리 Frida 세션을 먼저 대조한다. 기존 합성 등록 v1·v2는 커스텀 UI를 찾지 못했으므로 재실행하지 않는다. 런타임 표면을 크기 제한보다 작은 청크로 읽는 관찰 코드부터 별도 검토·승인하고, 정확한 UI 구조가 확인된 뒤에만 새 합성 입력 코드를 검토한다. 로컬 DB에 값이 실제 평문 저장되는지 확인한 뒤에만 `EFI-MA-21`을 확정하고, 생성한 정확한 합성 레코드를 삭제한 증적까지 남긴 후 확정 항목만 벤더 DOCX로 생성한다.
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
- pymobiledevice3 11.x의 `backup2 --only-regex`는 수신 payload 필터에서 `file_name/fileID`를 검사하지 않아 앱 경로 정규식만 쓰면 Manifest 행만 남고 실제 파일이 버려진다. 이번 검증은 런타임에서만 콜백을 보정해 Cyberone DB fileID 하나만 보존했으며 설치된 패키지는 수정하지 않았다.
- 저장소 루트의 실단말용 `config.yaml`은 의도적으로 로컬 도구를 활성화한다. 기본 Adapter 동작을 검사하는 전체 테스트는 `MSW_CONFIG=/tmp/msw-test-no-config.yaml`처럼 존재하지 않는 테스트 설정 경로를 지정해 로컬 장비 설정과 분리한다.

## 4. 참고

- `AGENTS.md` §0에 세션별 변경 이력, §3 구현 상태, §10 아직 자동화가 아닌 영역.
- `docs/CLAUDE_CODE_OPERATION.md` MCP·WSL2 실단말 절차, `docs/DOMESTIC_ASSESSMENT.md` 판정 정책, `docs/VALIDATION_LAB.md` 연습 앱.
