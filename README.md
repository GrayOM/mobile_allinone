# Mobile Security Workbench

Windows 10/11에서 브라우저로 사용하는 **AI 기반 모바일 자동 진단·증적 수집 플랫폼**의 실행 가능한 MVP다. 승인된 앱과 단말의 정적 분석, ADB, Frida, 프록시, AI 판정과 증적 원본을 하나의 로컬 작업 흐름으로 연결한다. Androguard·MobSF·APKiD·Semgrep·objection·drozer·pymobiledevice3·libimobiledevice의 검증된 패턴을 공통 Adapter와 원시 결과 보존 구조로 확장했다.

> 이 도구는 소유하거나 명시적으로 진단 권한을 받은 앱·단말에서만 사용한다. 상태 변경 네트워크 요청은 자동 재전송하지 않으며, AI 생성 Frida 스크립트는 구문 검사와 승인 전에는 실행하지 않는다.

## 현재 동작하는 데모

외부 단말과 도구가 없어도 다음 시나리오가 동작한다.

1. `run_windows.bat`으로 로컬 서버와 브라우저를 실행한다.
2. 대시보드에서 **Mock 전체 데모 시작**을 누른다.
3. 앱·단말·Frida 스크립트·Mock Proxy를 확인하고 진단을 시작한다.
4. 설치, 원본 실행, 캡처, Logcat, Frida, HTTP 흐름, AI 판정 상태가 실시간 화면에 표시된다.
5. 발견항목에서 화면·명령·스크립트·패킷·로그 타임라인을 확인한다.
6. 취약점별 HTML 증적 설명서를 열고 원본 파일을 내려받는다.
7. 통제 커버리지에서 MASTG 기준선과 자동·수동·미지원 상태를 확인한다.

Mock 데모 APK는 실행 중 로컬에서 생성되는 안전한 ZIP 기반 샘플이다. 실제 Android 단말에는 설치할 수 없으며 Mock Adapter 전용이다.

## Windows 설치

### 필수

- Windows 10/11
- Python 3.12와 Python Launcher(`py`)
- Node.js LTS와 npm

PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install_windows.ps1
.\run_windows.ps1
```

또는 탐색기/명령 프롬프트:

```bat
install_windows.bat
run_windows.bat
```

브라우저 주소는 기본 `http://127.0.0.1:8765`다. 서버는 기본적으로 loopback에만 바인딩된다.

추가 OSS 도구는 기본 설치와 분리되어 있다. 라이선스와 플랫폼 요구사항을 검토한 뒤 필요한 도구만 선택한다.

```powershell
.\install_oss_tools.ps1 -Frida -Mitmproxy -Semgrep
.\install_oss_tools.ps1 -APKiD -Objection -Pymobiledevice3 -Drozer -AcceptCopyleftLicenses
```

### 개발 실행

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
cd frontend
npm install
npm run build
cd ..
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8765
```

프론트 개발 서버가 필요하면 별도 터미널에서 실행한다.

```powershell
cd frontend
npm run dev
```

Vite 개발 서버는 `/api`를 `127.0.0.1:8765`로 프록시한다.

## 선택 도구

도구가 없거나 경로가 틀려도 서버는 종료되지 않는다. 설정 화면에 `not_configured`와 설치 안내를 표시한다.

| 도구 | 사용 기능 | 예시 설치/설정 |
|---|---|---|
| Androguard | 바이너리 AXML, APK 메타데이터·권한·컴포넌트 보완 | 기본 Python 의존성 |
| ADB | 단말 검색, 설치·삭제, 실행·종료, 캡처·녹화, Logcat, 파일, 프로세스, 포트 포워딩 | Android SDK Platform-Tools |
| apktool | 바이너리 AndroidManifest.xml 해석 | apktool 공식 Windows 설치 |
| jadx | APK 코드 디컴파일 | jadx Windows 릴리스 |
| aapt / apkanalyzer | APK 메타데이터 보완 | Android SDK Build/Command-line Tools |
| frida-tools | Spawn·Attach와 스크립트 실행 | `py -m pip install frida-tools` |
| mitmproxy | 실제 HTTP(S) 흐름 캡처 | `py -m pip install mitmproxy` |
| APKiD | 패커·컴파일러·난독화·anti-analysis 시그니처 | `install_oss_tools.ps1 -APKiD -AcceptCopyleftLicenses` |
| Semgrep | JADX 코드에 로컬 Android 보안 규칙 적용 | `install_oss_tools.ps1 -Semgrep` |
| MobSF | 별도 서버의 APK·IPA REST 분석 결과 통합 | `.env`의 `MOBSF_URL`, `MOBSF_API_KEY` |
| objection | 승인 경계가 있는 런타임 환경 탐색 | `install_oss_tools.ps1 -Objection -AcceptCopyleftLicenses` |
| drozer | Android IPC·공격 표면 조회 | `pipx install drozer`와 승인된 단말 Agent |
| pymobiledevice3 | Windows USB iOS 탐색·앱·실행·포트 Adapter | opt-in Python 설치 |
| libimobiledevice | iOS 정보·앱·syslog·스크린샷 | Windows 빌드 실행 파일 경로 지정 |
| OpenSSH | iOS SSH Adapter | Windows 선택적 기능 OpenSSH Client |
| Node.js | Frida JavaScript 구문 검사 | Node.js LTS |

실행 파일 이름 대신 절대 경로를 `config.yaml`에 지정할 수 있다.

```yaml
tools:
  adb: C:\Android\platform-tools\adb.exe
  apktool: C:\Tools\apktool\apktool.bat
  jadx: C:\Tools\jadx\bin\jadx.bat
  frida: C:\project\mobile_allinone\.venv\Scripts\frida.exe
  mitmdump: C:\project\mobile_allinone\.venv\Scripts\mitmdump.exe
  apkid: C:\project\mobile_allinone\.venv\Scripts\apkid.exe
  semgrep: C:\project\mobile_allinone\.venv\Scripts\semgrep.exe
  pymobiledevice3: C:\project\mobile_allinone\.venv\Scripts\pymobiledevice3.exe
```

화면에서 경로를 저장한 경우 서버 재시작 후 적용된다.

## AI 설정

`.env.example`을 `.env`로 복사한다. 키를 코드나 `config.yaml`에 넣지 않는다.

```dotenv
NVIDIA_API_KEY=
NVIDIA_MODEL=meta/llama-3.1-70b-instruct
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-6
MSW_MASK_EXTERNAL_AI_DATA=true
```

정책:

1. 프로젝트의 `AI 분석 사용`이 꺼져 있으면 호출하지 않는다.
2. `외부 AI 전송 허용`이 꺼져 있으면 NVIDIA·Claude로 보내지 않는다.
3. Mock 프로젝트는 `MockAIProvider`만 사용한다.
4. Live 프로젝트는 NVIDIA를 먼저 호출한다.
5. 실패, 속도 제한, Schema 오류 또는 품질 기준 미달이면 Claude로 fallback한다.
6. 토큰, 쿠키, 이메일, 전화번호, 실제 도메인 후보를 전송 전 마스킹한다.
7. Provider, 모델, 상태, 품질 점수와 오류를 `ai_invocations`에 남긴다.
8. 원문 응답은 파싱 성공 여부와 관계없이 프로젝트 데이터 디렉터리에 보존할 수 있다.
9. Frida 실패 후보 생성은 별도 JSON Schema를 검증하고 구문 검사 후 `pending_approval`로만 저장한다.
10. 진단의 자동 수정 옵션도 후보를 실행하지 않으며 사용자가 Frida 라이브러리에서 승인해야 한다.

NVIDIA 연동은 OpenAI 호환 `POST /v1/chat/completions`, Claude 연동은 Messages `POST /v1/messages`와 JSON Schema `output_config`를 사용한다.

## 실제 Android 연결

1. 승인된 Android 단말에서 USB 디버깅을 활성화한다.
2. `adb devices -l`에서 승인 상태를 확인한다.
3. 설정 화면에서 ADB와 Frida 경로가 `available`인지 확인한다.
4. 연결 단말 화면에서 실제 단말을 선택한다.
5. 프로젝트에 실제 APK를 업로드한다.
6. 진단 설정에서 `Android ADB` 단말과 프록시를 선택한다.

구현된 ADB 기능:

- 연결 단말 검색과 속성 조회
- 사용자 설치 패키지 목록
- APK 설치·삭제
- 앱 실행·강제 종료
- PNG 화면 캡처
- `screenrecord` 녹화와 파일 가져오기
- Logcat 스냅샷
- 파일 가져오기
- 앱 PID 확인
- Frida Server 프로세스 확인
- USB TCP 포트 포워딩

ADB 명령은 shell 문자열 결합 없이 인자 배열로 실행하고, 명령별 타임아웃과 stdout/stderr를 증적에 남긴다.

## iOS on Windows

연결 단말 화면의 **iOS 단말 등록**에서 SSH 호스트, 포트, 사용자와 Frida endpoint를 등록할 수 있다. 비밀번호는 저장하지 않으며 키 기반 Windows OpenSSH 연결을 가정한다.

현재 Adapter는 우선순위대로 libimobiledevice, pymobiledevice3, SSH/Frida를 사용한다.

- USB 단말 탐색과 정보: `idevice_id`/`ideviceinfo`, pymobiledevice3 fallback
- 설치 앱 목록·서명된 IPA 설치/삭제: `ideviceinstaller`, pymobiledevice3 Adapter
- 앱 실행·프로세스: pymobiledevice3 또는 탈옥 단말 SSH
- syslog·스크린샷: `idevicesyslog`, `idevicescreenshot`
- 파일: 탈옥 단말 SCP, 비탈옥 AFC 범위는 `manual_required`
- Frida 상태: `frida-ps`, SSH 프로세스 확인
- USB 포트 포워딩: pymobiledevice3 Adapter
- IPA 서명·재서명과 macOS 전용 작업: `manual_required`
- Mock iOS Device: 항상 사용 가능

도구 버전이나 단말 상태가 요구조건을 만족하지 않으면 성공으로 처리하지 않고 실제 stderr와 상태를 남긴다.

## 프록시

### mitmproxy

`MitmProxyAdapter`는 `mitmdump`를 실제 프로세스로 시작하고 `scripts/mitm_capture_addon.py` addon으로 요청·응답을 JSON Lines에 저장한다.

- Method, URL, 요청·응답 Header/Body, Status 저장
- Authorization, Cookie, API Key, Token, 이메일·전화번호 후보 표시
- JSON 원본 증적 저장
- 본문은 흐름당 1MB로 제한
- 상태 변경 요청 자동 재전송 없음

단말 프록시는 Windows PC의 LAN IP와 설정한 포트를 사용한다. HTTPS CA 설치는 승인된 테스트 단말에서만 수행한다.

### Burp Suite / Fiddler

현재 `manual_required` Adapter다. 리스너·단말 설정 안내와 HAR 가져오기 구조를 제공하며, 자동 프로세스 제어를 성공으로 위장하지 않는다.

## Frida 라이브러리

```text
scripts/frida/
├─ Android/
│  ├─ Root Detection/
│  ├─ SSL Pinning/
│  └─ Anti-Debug/
└─ iOS/
   └─ Jailbreak Detection/
```

각 스크립트는 플랫폼, 카테고리, 대상 프레임워크, 적용 조건, 위험도, 승인 상태, 구문 상태, 성공·실패 횟수를 저장한다. 내장 스크립트는 우회 성공을 가짜로 만들지 않는 관찰용 후크다.

사용자·AI 후보는:

1. `pending_approval`로 저장
2. Node.js `--check` 구문 검사
3. 사용자 승인
4. 승인된 스크립트만 Spawn·Attach 또는 Mock 실행
5. 실행 명령, 전체 스크립트, 메시지와 오류를 증적으로 저장

스크립트 화면의 AI 후보 생성기는 관련 코드·실패 로그만 입력받는다. 프로젝트의 외부 전송 정책과 마스킹을 적용하고 NVIDIA 실패 시 Claude로 fallback한다. Mock Provider로 외부 전송 없는 승인 흐름도 검증할 수 있다.

## 정적 분석 범위

기본 분석기는 자체 ZIP/문자열 휴리스틱과 Androguard를 함께 사용한다.

- APK·IPA ZIP 구조, DEX/아키텍처/네이티브 라이브러리
- 텍스트 AndroidManifest.xml, Info.plist
- 권한, exported 컴포넌트, Intent Filter, URL Scheme
- URL·IP·JWT·API Key·토큰·개인키 후보
- WebView/WKWebView와 JavaScript Interface
- SharedPreferences, SQLite, UserDefaults, Keychain 신호
- 암호화 API, 인증서 고정
- 루팅·탈옥, Frida·후킹, 디버거 탐지
- 서명·무결성, 난독화 신호

추가 분석기는 독립적으로 병렬 실행된다.

- apktool/jadx: 디코딩과 디컴파일 원본
- APKiD: 보호·난독화·패커 시그니처
- Semgrep: `rules/semgrep`의 보수적인 로컬 규칙
- MobSF: 설정된 별도 REST 서버의 APK·IPA 결과

각 실행은 도구명·버전·상태·인자 배열·원문 경로·SHA-256을 `tool_runs`에 남긴다. 각 원시 탐지는 규칙 ID와 fingerprint를 `raw_findings`에 보존하고, 상관분석된 발견항목도 `finding_sources`로 원출처를 역추적할 수 있다. 어떤 한 도구가 실패해도 다른 분석을 계속한다.

## MASTG 통제 커버리지

앱 분석 시 플랫폼별 MASTG 기준선을 만들고 정적 자동화 상태를 기록한다. 진단 실행은 기준선을 복제해 로그·Frida·프록시 증적 ID를 실행별 상태에 연결한다.

- `static`, `dynamic`, `hybrid`, `manual` 자동화 분류
- `completed`, `manual_required`, `unsupported`, `not_configured` 실행 상태
- `needs_review`, `unknown`, `informational` 판정 신호
- legacy MASTG ID와 upstream replacement ID·공식 링크

카탈로그는 OWASP 원문을 복제하지 않고 식별자·링크·로컬 실행 결과만 저장한다.

## 증적 저장

기본 데이터 구조:

```text
data/
├─ workbench.db
├─ uploads/<project-id>/
├─ analysis/<uploaded-file-stem>/
├─ evidence/<run-id>/
├─ proxy/
├─ ai_raw/
└─ reports/<finding-id>.html
```

기본 캡처 시점:

- 앱 실행 직후
- 우회 적용 전
- 우회 적용 후
- 로그인 완료 후(로그인 일시정지 사용 시)
- 동적 테스트 후

모든 파일 증적은 SHA-256을 계산한다. HTML 설명서는 전체 보고서가 아니라 취약점별 타임라인이며, 화면·명령·Frida 스크립트·패킷·로그와 다운로드 가능한 원본을 포함한다.

## 상태 의미

| 상태 | 의미 |
|---|---|
| `available` | 현재 실행 또는 연결 가능 |
| `not_configured` | 실행 파일, 키 또는 연결 설정 없음 |
| `unsupported` | 현재 Adapter/플랫폼이 지원하지 않음 |
| `manual_required` | 자동화하지 않고 사용자 작업 필요 |
| `failed` | 실행을 시도했지만 실패 |

## API

서버 실행 후 Swagger UI: `http://127.0.0.1:8765/docs`

주요 경로:

- `/api/projects`, `/api/projects/{id}/apps/upload`
- `/api/apps/{id}/reanalyze`, `/api/apps/{id}/analysis/overview`
- `/api/devices`, `/api/devices/action`, `/api/devices/ios/profiles`
- `/api/runs`, `/api/runs/{id}/pause|resume|stop`
- `/api/runs/{id}/ws`
- `/api/frida/scripts`, `/api/frida/scripts/generate`, `/api/frida/scripts/{id}/approve|execute`
- `/api/analysis/tools`, `/api/runtime/adapters`, `/api/runtime/execute`
- `/api/coverage`, `/api/findings/{id}/sources`
- `/api/runs/{id}/flows`, `/api/runs/{id}/evidence`
- `/api/findings`, `/api/findings/{id}/report`
- `/api/proxy/adapters`, `/api/ai/test`, `/api/settings`

## 테스트

```powershell
.\.venv\Scripts\python.exe -m pytest
cd frontend
npm audit --audit-level=high
npm run build
```

자동 테스트는 다음을 검증한다.

- 외부 도구 없는 APK 분석
- `not_configured` 상태
- Mock Device 캡처·로그
- iOS `manual_required`
- Mock Proxy 민감정보 후보
- Burp 수동 연동 상태
- NVIDIA 실패 → Claude fallback
- AI Frida 후보 JSON Schema·구문 검사·승인 대기
- Frida 후보 승인 전 실행 차단
- 분석기 원시 결과·MASTG 커버리지 저장
- 고위험 objection/drozer 작업 승인 차단
- Mock 업로드 → 진단 → 증적 → 발견항목 → HTML 전체 흐름

## Docker 선택 실행

Docker는 Mock 데모와 웹 UI 용도다. USB ADB·Windows Fiddler·로컬 Frida 접근은 Windows 직접 실행을 권장한다.

```powershell
docker compose up --build
```

## 프로젝트 구조

```text
backend/app/
├─ api/              # REST·WebSocket
├─ analyzers/        # APK·IPA 정적 분석
├─ catalog/          # MASTG 통제 카탈로그·실행 기준선
├─ devices/          # Android/iOS/Mock DeviceAdapter
├─ frida/            # 실행기·라이브러리 시드
├─ proxy/            # mitmproxy/Burp/Fiddler/Mock
├─ ai/               # NVIDIA/Claude/Mock과 fallback
├─ evidence/         # 원본·타임라인·HTML
├─ orchestration/    # 진단 상태 머신
├─ runtime/          # objection·drozer 승인형 Adapter
└─ database/         # SQLite 모델·세션
frontend/src/
├─ components/
├─ pages/
└─ router.tsx        # 외부 Router 없는 History API 라우팅
rules/
└─ semgrep/          # 프로젝트 자체 Android 보안 규칙
scripts/
├─ frida/
└─ mitm_capture_addon.py
tests/
docs/
```

상세 구현 계획은 [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md), OSS 통합·라이선스 경계는 [docs/OSS_INTEGRATIONS.md](docs/OSS_INTEGRATIONS.md)를 참고한다.

## 남은 확장 영역

- 제조사 보안통제별 실제 우회 내성 스크립트(현재 내장 스크립트는 동작을 바꾸지 않는 관찰용)
- 실제 제조사별 Android 보안 솔루션/키패드 전용 Adapter
- 장시간 Logcat·화면 녹화의 스트리밍 제어 UI
- Fiddler/Burp 프로세스 API 자동 연동
- DB/SharedPreferences/Keychain 구조화 뷰어
- 사용자 승인 기반 딥링크·노출 컴포넌트 호출 UI
- 앱 동작 전후 파일 시스템 diff
- 조직용 사용자 인증·권한·감사 로그(현재는 loopback 단일 사용자)
