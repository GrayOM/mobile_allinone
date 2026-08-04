# Mobile Security Workbench — 세션 인수인계

> 최종 갱신: 2026-08-04
> 작업 위치: `/mnt/c/Users/PSM/Desktop/project/mobile_allinone`
> 새 세션에서는 이 파일을 먼저 읽고, 완료된 기능을 처음부터 다시 만들지 않는다.

## 1. 프로젝트 목적과 절대 원칙

이 프로젝트는 Windows 10/11에서 브라우저로 사용하는 로컬 모바일 앱 보안 진단·증적 수집 플랫폼이다. 사용자가 소유하거나 명시적으로 진단 권한을 받은 앱과 단말만 대상으로 한다.

핵심 원칙:

- 실제 구현이 없는 기능을 성공으로 표시하지 않는다.
- 실행할 수 없으면 `not_configured`, `unsupported`, `manual_required`, `failed`로 구분한다.
- 상태 변경 HTTP 요청을 자동으로 재전송하지 않는다.
- AI가 만든 Frida 스크립트는 자동 실행하지 않는다.
- AI 스크립트는 JSON Schema 검증, JavaScript 구문 검사, 사용자 승인을 거친 뒤에만 실행한다.
- API 키와 비밀정보는 `.env`에서만 읽고 코드·`config.yaml`에 저장하지 않는다.
- 외부 AI 전송은 프로젝트의 `ai_enabled`, `external_ai_allowed` 정책을 따른다.
- 프로젝트 실행 모드는 `mock | live`로 분리하며 Live에서 Mock Adapter로 fallback하지 않는다.
- Mock에서 생성한 앱·실행·증적·패킷·발견항목·AI 결과에는 `synthetic=true`를 영구 보존한다.
- 기존 사용자 파일과 관련 없는 변경은 건드리지 않는다.

## 2. 현재 기술 구조

- Backend: Python 3.12, FastAPI, SQLAlchemy, SQLite
- Frontend: React 18, TypeScript, Vite
- 실시간 상태: WebSocket
- 작업 실행: 내부 `asyncio` Task 기반 `DiagnosticOrchestrator`
- 설정: `.env`, `config.yaml`
- 테스트: pytest
- Windows 실행: PowerShell/BAT
- Docker: Mock 데모와 웹 UI 위주

주요 디렉터리:

```text
backend/app/
├─ api/              REST·WebSocket API
├─ analyzers/        자체 분석 + OSS Analyzer Adapter + 상관분석
├─ catalog/          OWASP MASTG 통제 카탈로그
├─ devices/          Android/iOS/Mock DeviceAdapter
├─ frida/            스크립트 라이브러리·구문검사·실행
├─ proxy/            mitmproxy/Burp/Fiddler/Mock ProxyAdapter
├─ ai/               NVIDIA/Claude/Mock Provider와 fallback
├─ runtime/          objection/drozer 승인형 Adapter
├─ orchestration/    진단 상태 머신
├─ evidence/         증적 원본·타임라인·HTML 설명서
└─ database/         SQLite 모델·세션

frontend/src/
├─ components/
├─ pages/
└─ router.tsx

rules/semgrep/       프로젝트 자체 Android 보안 규칙
scripts/frida/       내장 관찰용 Frida 스크립트
tests/               단위·API·Mock E2E 테스트
```

## 3. 현재 구현 완료 상태

### 기본 MVP

- 프로젝트 생성·수정·삭제
- APK·IPA 등록과 자동 플랫폼 판별
- 앱 메타데이터·분석 결과 조회
- 과거 진단 실행 조회
- 진단 시작·일시정지·재개·중지
- Mock Android·Mock iOS·Mock Proxy·Mock AI 전체 데모
- 취약점 목록·상세·증적 타임라인
- 취약점별 HTML 증적 설명서
- Windows 로컬 웹 실행

### 운영 안전 경계

- 프로젝트 `run_mode`를 `mock | live`로 분리하고 앱·진단 이력이 생긴 뒤 변경을 차단한다.
- Live 프로젝트는 Mock Device·Proxy·AI를 거부하고, 알 수 없는 Adapter는 422로 종료한다.
- Mock 결과에는 DB/API/UI 전 구간 `synthetic=true` 또는 `SYNTHETIC MOCK` 표식을 남긴다.
- 단말별 활성 Run 하나만 허용하고, mitmproxy 포트는 실행마다 동적 할당·임대한다.
- 중지·실패·서버 종료 시 외부 프로세스 트리를 정리하고, 재시작 시 활성 Run을 `interrupted`로 복구한다.
- 실행 중인 Run이 있는 프로젝트 삭제는 409로 차단한다.
- 장시간 외부 작업 전 DB transaction을 commit해 SQLite 잠금을 유지하지 않는다.

### Android

- ADB 단말 탐색
- 패키지 목록, APK 설치·삭제
- 앱 실행·종료
- 스크린샷·화면 녹화
- Logcat, 파일 가져오기, 프로세스 확인
- Frida Server 상태 확인
- USB 포트 포워딩

### iOS on Windows

`IOSDeviceAdapter`가 다음 순서로 가능한 기능을 사용한다.

- libimobiledevice: `idevice_id`, `ideviceinfo`, `ideviceinstaller`, `idevicesyslog`, `idevicescreenshot`
- pymobiledevice3: USB 탐색, 앱 목록·실행, 포트 Adapter
- SSH/SCP: 탈옥 단말 앱·프로세스·로그·파일
- `frida-ps`: Frida 연결 상태
- IPA 서명·재서명과 macOS 의존 작업은 `manual_required`
- 비탈옥 단말의 임의 컨테이너 파일 접근도 지원 범위 밖이면 `manual_required`

### 정적 분석기 연합

다음 분석 결과를 공통 구조로 통합한다.

- `native_static`: ZIP·Manifest/Plist·문자열·코드 신호 휴리스틱
- Androguard: 기본 Python 의존성, APK 바이너리 AXML·메타데이터
- apktool/jadx: 선택 외부 도구
- APKiD: 보호·패커·난독화·anti-analysis 시그니처
- Semgrep: JADX 결과에 `rules/semgrep` 규칙 적용
- MobSF: 별도 서버 REST API 연동

각 도구 실행은 `tool_runs`에 버전, 상태, 인자 배열, 오류, 원문 경로와 SHA-256을 저장한다. 원시 탐지는 `raw_findings`, 정규화된 발견항목의 출처는 `finding_sources`에 저장한다. 도구 하나가 실패해도 나머지 분석은 계속한다.

### MASTG 통제 커버리지

- `backend/app/catalog/mastg.py`에 Android/iOS 통제 기준선이 있다.
- OWASP 원문 전체를 복제하지 않고 ID, 공식 링크, replacement ID, 로컬 실행 상태만 저장한다.
- 앱 분석 시 run 없는 기준선 `ControlTest`를 만든다.
- 진단 실행 시 기준선을 실행별로 복제하고 증적 ID를 연결한다.
- UI `/coverage`에서 MASVS 그룹, MASTG ID, 자동화 방식, 상태, 판정 신호를 표시한다.
- 재분석할 때는 기준선만 교체하고 과거 실행별 통제 이력은 보존해야 한다.

### Frida와 AI

- 내장 스크립트는 동작을 바꾸지 않는 저위험 관찰용이다.
- 사용자 스크립트와 AI 후보는 `pending_approval`로 저장한다.
- NVIDIA가 1차, Claude가 fallback이다.
- Mock Provider로 외부 전송 없는 승인 흐름을 시험할 수 있다.
- Frida 실패 시 옵션이 켜져 있으면 관련 코드·로그·기존 스크립트만 AI에 전달해 수정 후보를 만든다.
- 생성 후보는 저장만 하고 절대 자동 실행하지 않는다.
- Provider, 모델, 상태, 품질과 원문 경로는 `ai_invocations`에 기록한다.
- Node.js 구문 상태가 `available`인 스크립트만 승인·실행할 수 있다.
- 승인자·승인 시각·승인 당시 SHA-256을 보존하고 내용이 달라지면 승인을 자동 취소한다.
- AI 응답은 여러 Finding을 생성하며, 각 Finding은 현재 Run에 속한 증적 ID만 연결한다.
- 낮은 신뢰도 결과는 `needs_review`로 남기고 AI 원문 저장은 기본 비활성화한다.
- 외부 AI 입력은 Header/JSON/Query/Cookie/개인정보/고엔트로피 문자열을 구조적으로 마스킹한다.

### 런타임 OSS Adapter

- objection: 환경·파일 조회와 승인형 보안통제 작업
- drozer: 패키지·공격 표면·Provider 조회와 승인형 컴포넌트 호출
- 읽기 작업 외의 중·고위험 작업은 `approved=true`가 없으면 `manual_required`

### 프록시

- mitmproxy는 실제 `mitmdump` 프로세스와 addon으로 JSON Lines 흐름을 수집한다.
- 요청·응답, Header/Body, Status와 민감정보 후보를 저장한다.
- Burp/Fiddler는 현재 수동 연동 Adapter다.
- POST·PUT·PATCH·DELETE 요청을 자동 재전송하지 않는다.
- mitmproxy는 특정 Windows LAN IP에만 바인딩하고 진단 단말의 출발지 IP만 addon에서 허용한다.
- 동적 테스트 종료 후 프록시 Stop·Flush·최종 Drain 순서로 패킷을 저장한다.

### 입력·외부 도구 방어

- APK/IPA는 Entry 수, 전체·개별 비압축 크기, 압축률, 중첩 압축, 경로, 중복, 암호화, symlink를 사전 검사한다.
- 제한 초과는 warning이 아니라 422 rejected로 종료하며 외부 분석기를 실행하지 않는다.
- 외부 분석 도구는 프로세스 그룹으로 실행하고 wall time·프로세스 트리 메모리·CPU 시간을 제한한다.

## 4. 주요 데이터 모델

기존 모델 외에 추가된 핵심 테이블:

- `tool_runs`: 분석 도구 실행 이력
- `raw_findings`: 도구별 원시 탐지
- `finding_sources`: 정규화 발견항목과 원시 탐지 연결
- `control_tests`: 앱 기준선 및 진단 실행별 MASTG 상태
- `ai_invocations`: AI Provider·모델·상태·원문 기록

현재 Alembic은 사용하지 않는다. 안전 경계 컬럼은 `schema_migrations`와 시작 전 DB 백업을 사용하는 명시적 SQLite migration으로 추가한다. 이후 스키마 변경도 `create_all`만 믿지 말고 같은 방식 또는 Alembic 도입 후 진행한다.

분석 출력 디렉터리는 DB의 artifact ID가 아니라 업로드 파일의 UUID stem을 사용한다.

```text
data/
├─ workbench.db
├─ uploads/<project-id>/
├─ analysis/<uploaded-file-stem>/
├─ evidence/<run-id>/
├─ proxy/
├─ ai_raw/
└─ reports/
```

## 5. 주요 API

```text
/api/projects
/api/projects/{id}/apps/upload
/api/apps/{id}/reanalyze
/api/apps/{id}/analysis/overview

/api/devices
/api/devices/action
/api/devices/ios/profiles

/api/runs
/api/runs/{id}/pause|resume|stop
/api/runs/{id}/ws
/api/runs/{id}/evidence
/api/runs/{id}/flows

/api/frida/scripts
/api/frida/scripts/generate
/api/frida/scripts/{id}/approve|execute

/api/analysis/tools
/api/runtime/adapters
/api/runtime/execute
/api/coverage
/api/findings
/api/findings/{id}/sources
/api/findings/{id}/report

/api/proxy/adapters
/api/ai/test
/api/settings
```

## 6. UI 상태

필수 화면은 모두 연결되어 있다.

- 대시보드
- 프로젝트·앱 등록
- 연결 단말
- 진단 설정
- 실시간 진단
- 발견항목 목록·상세
- 증적 타임라인
- Frida 라이브러리
- MASTG 통제 커버리지
- 설정과 OSS Adapter 상태

디자인 방향은 산업용 로컬 보안 워크벤치다.

- 기존 teal/orange/ink 색상과 Bahnschrift/Cascadia 계열을 유지한다.
- 통제 커버리지는 일반 카드 모음이 아니라 밀도 높은 “통제 신호 원장”이 핵심 시각 요소다.
- 새 UI를 만들 때 불필요한 둥근 카드·그라데이션·과도한 애니메이션을 추가하지 않는다.
- 1440×1000과 390×844 브라우저 검증이 완료되었다.

## 7. 설치와 실행

Windows 기본 설치:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install_windows.ps1
.\run_windows.ps1
```

BAT:

```bat
install_windows.bat
run_windows.bat
```

기본 주소:

```text
http://127.0.0.1:8765
```

개발 실행:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
cd frontend
npm ci
npm run build
cd ..
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8765
```

선택 OSS 도구:

```powershell
.\install_oss_tools.ps1 -Frida -Mitmproxy -Semgrep
.\install_oss_tools.ps1 -APKiD -Objection -Pymobiledevice3 -Drozer -AcceptCopyleftLicenses
```

MobSF, jadx, apktool, Android SDK와 libimobiledevice는 URL 또는 실행 파일 경로를 설정한다. 설치 실패를 성공으로 처리하면 안 된다.

Androguard 4.1.x와 다른 보안 도구의 호환성을 위해 `cryptography>=46.0.6,<48`로 제한되어 있다. 특별한 근거 없이 이 상한을 제거하지 않는다.

## 8. 환경설정과 비밀정보

`.env.example`을 `.env`로 복사한다.

```dotenv
NVIDIA_API_KEY=
NVIDIA_MODEL=meta/llama-3.1-70b-instruct
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-6

MOBSF_URL=
MOBSF_API_KEY=
MSW_MASK_EXTERNAL_AI_DATA=true
MSW_STORE_AI_RAW_RESPONSES=false
MSW_PROXY_LISTEN_HOST=127.0.0.1
```

실행 파일은 `config.yaml` 또는 설정 화면에서 지정한다. 설정 화면 저장 후 서버 재시작이 필요하다.

## 9. 현재 검증 결과

마지막 검증:

```text
python3 -m compileall -q backend   통과
pytest -q                          22 passed
npm run build                     통과
npm audit --audit-level=high      0 vulnerabilities
```

추가 수동 검증:

- Androguard 4.1.4와 공식 테스트 APK로 바이너리 Manifest 해석 성공
- 패키지명 `tests.androguard`, 상태 `available`, 원문 SHA-256 생성 확인
- Mock 데모 전체 실행과 HTML 증적 설명서 확인
- AI Mock Frida 후보 생성 후 `pending_approval` 확인
- 승인 전 실행 요청이 409로 차단되는 것 확인
- 통제 커버리지 데스크톱·모바일 렌더링과 브라우저 콘솔 오류 0건 확인
- Live/Mock 혼용 차단, 실행 중 삭제 차단·중지 대기, ZIP 경로·압축률 거부 확인
- 구조 기반 AI 마스킹과 Finding별 증적 ID 연결 확인
- 1440×1000·390×844에서 설정 화면과 Mock/Live 진단 경계를 확인하고 브라우저 콘솔 오류 0건 확인

테스트 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest
cd frontend
npm run build
npm audit --audit-level=high
```

## 10. 아직 실제 자동화가 아닌 영역

다음 항목은 완료된 것처럼 처리하면 안 된다.

- Fiddler/Burp 프로세스 API 자동 제어
- 제조사별 보안 솔루션·보안 키패드·RASP 전용 검증 Adapter
- macOS가 필요한 IPA 서명·재서명
- 모든 iOS 버전/단말 조합의 파일·화면 수집 보장
- DB/SharedPreferences/Keychain 구조화 뷰어
- 앱 실행 전후 파일 시스템 diff
- 사용자 승인형 딥링크·노출 컴포넌트 호출 전용 UI
- 장시간 Logcat·화면 녹화 스트리밍 제어 UI
- 조직용 인증·역할·감사 로그

## 11. 새 세션 시작 체크리스트

새 세션은 다음 순서로 시작한다.

1. 이 `AGENTS.md`와 `README.md`, `docs/OSS_INTEGRATIONS.md`를 읽는다.
2. 사용자 요청이 기존 완료 기능인지 새 변경인지 구분한다.
3. `rg --files`로 실제 파일을 확인하고 문서 내용만 믿지 않는다.
4. 이 디렉터리는 현재 Git 저장소가 아닐 수 있으므로 `git status` 실패를 오류로 오인하지 않는다.
5. 기존 `data/`, `.env`, `config.yaml`과 사용자 변경을 보존한다.
6. 변경 전에 관련 Adapter·API·UI·테스트를 함께 찾는다.
7. 구현 후 최소 `pytest -q`와 `frontend`의 `npm run build`를 실행한다.
8. UI 변경이면 데스크톱과 모바일 크기를 모두 확인한다.
9. 외부 도구가 없다는 이유로 Mock 성공값을 실제 Adapter 결과로 사용하지 않는다.
10. 완료 시 구현·변경 파일·실행법·테스트·Mock/수동 영역을 명확히 보고한다.

## 12. 다음 확장 우선순위

사용자가 별도 우선순위를 주지 않으면 다음 순서가 합리적이다.

1. DB/SharedPreferences/Keychain 구조화 뷰어와 민감정보 상관분석
2. 실행 전후 파일 시스템 diff와 증적 연결
3. 사용자 승인형 딥링크·노출 컴포넌트 호출 UI
4. Burp/Fiddler 가져오기·세션 연동 강화
5. 실제 iOS 단말 매트릭스별 검증과 AFC/HouseArrest 확장
6. 제조사 보안통제용 플러그인형 검증 팩
7. 장시간 수집 작업의 취소·재연결·스트리밍 제어
8. 범용 SQLite/Alembic migration 체계와 조직용 인증·감사 로그

## 13. 참고 문서

- `README.md`: 사용자 설치·운영 설명
- `docs/IMPLEMENTATION_PLAN.md`: 전체 구조
- `docs/OSS_INTEGRATIONS.md`: OSS 경계·라이선스·설치
- `THIRD_PARTY_NOTICES.md`: 제3자 고지
- `.env.example`, `config.example.yaml`: 설정 예시

이 파일은 구현 상태나 안전 경계가 바뀌면 같은 작업에서 함께 갱신한다.
