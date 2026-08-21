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
7. 통제 커버리지에서 선택한 국내 진단 기준의 판정·증적 상태와 MASTG 보조 기준을 확인한다.

Mock 데모 APK는 실행 중 로컬에서 생성되는 안전한 ZIP 기반 샘플이다. 실제 Android 단말에는 설치할 수 없으며 Mock Adapter 전용이다.

## 국내 취약점 진단 프로필

프로젝트를 만들 때 다음 중 하나를 고정 선택한다.

1. **주요정보통신기반시설**: 제공된 모바일 앱 보안 권고안의 27개 항목
2. **전자금융기반시설**: 제공된 2026 보안 권고안의 56개 항목

선택한 프로필만 앱 기준선과 Run 판정 원장에 생성된다. 앱이나 Run 이력이 생긴 뒤에는 기준을 바꿀 수 없다. `/coverage`의 국내 기준 원장이 주 판정 화면이며 OWASP MASTG는 교차 확인용 보조 원장이다.

국내 기준 원장은 항목별 실행 경계를 `NOW`, `DEVICE`, `SERVER`, `MANUAL`로 분리한다. 실제 단말이 필요한 항목은 완료로 표시하지 않고 `device_required`로 남기며, 단말 없이 가능한 정적 분석·AI 사전 분류·수동 증적 준비·테스트 절차 정의는 계속 진행할 수 있다. 전체 83개 항목의 구조화된 매트릭스는 `/api/assessment/execution-matrix`에서 확인한다.

APK·IPA 업로드와 재분석이 성공하면 선택한 프로필의 앱별 점검 계획을 자동 생성한다. 계획은 현재 앱 SHA-256에 고정되며 NOW 항목의 정적 후보·통제 신호를 즉시 선별하고, 나머지는 `waiting_device`, `waiting_server_scope`, `waiting_manual_review`로 배차한다. 정적 후보가 없다는 사실은 양호 판정이 아니며 `not_tested`를 유지한다. `/coverage`의 **앱 점검 배차판**에서 각 lane을 필터링하고 계획을 다시 계산할 수 있다. API는 `GET /api/apps/{app-id}/assessment/plan`과 `POST /api/apps/{app-id}/assessment/plan/refresh`다.

정적 문자열·Manifest 신호만으로는 취약점을 확정하지 않는다. 같은 Live Run에서 기준에 맞는 재현 결과와 필수 원본 증적이 모두 연결되거나, 승인된 수동 검토자가 원본 증적을 선택해 판정을 기록해야 `confirmed`가 된다. 예를 들어 루팅·탈옥 항목은 변조 상태 증적, 대상 앱 프로세스 실행 증적, 화면 증적이 함께 있어야 한다. `not_vulnerable`과 `not_applicable`은 상태만 기록하며 별도 증적을 요구하거나 생성하지 않는다. Mock 결과는 같은 흐름을 연습할 수 있지만 항상 `synthetic=true`이며 실제 진단 결과로 사용할 수 없다.

진단 Run이 안전 일시정지되거나 종료되면 국내 기준 원장의 **취약 판정 작업**에서 항목별 사건 파일을 연다. 같은 Run에서 수집된 증적 중 필수 유형과 일치하는 원본만 선택할 수 있으며, 수동 첨부는 해당 항목에 고정되어 다른 항목에서 재사용할 수 없다. 취약 확정은 검토자·판정 근거·기준 수행 확인과 필수 증적이 모두 있어야 저장된다. 양호·해당없음·추가 검토는 증적 선택 UI를 닫고 상태와 사유만 저장한다.

종료되거나 안전 일시정지된 Run에서는 **AI 증적 우선순위**를 계산할 수 있다. NVIDIA 우선·Claude fallback 또는 Mock AI가 미판정 항목과 현재 Run 증적의 관련성을 추천하면, 서버가 현재 프로필의 정확한 항목 ID, 같은 Run의 증적 ID, 항목별 필수 증적 유형과 수동 첨부 귀속을 다시 검증한다. 결과는 검토 순서와 화면 선택 후보로만 제공하며 판정, 증적 영구 연결, DOCX 수록을 자동 수행하지 않는다. Mock 추천 원장에는 `SYNTHETIC MOCK`을 표시한다.

상세 판정 흐름과 API는 [`docs/DOMESTIC_ASSESSMENT.md`](docs/DOMESTIC_ASSESSMENT.md)에 정리되어 있다.

Run에서 취약 확정 항목이 하나 이상 있으면 국내 기준 원장에서 **취약점만 DOCX**를 내려받을 수 있다. 이 문서는 `confirmed` 항목, 판정 기준, 재현 절차, 연결 증적, 조치 권고만 포함하며 양호·해당없음·미확정 항목은 수록하지 않는다. 확정 항목이 없으면 서버가 409로 생성을 거부한다.

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

### Linux / macOS 로컬 실행

Python 3.12, Node.js LTS와 npm이 설치된 POSIX 환경에서는 다음 스크립트로 의존성 설치·프론트엔드 빌드·로컬 서버 실행을 한 번에 수행할 수 있다.

```bash
chmod +x scripts/run.sh
./scripts/run.sh --install
```

이후 실행은 `./scripts/run.sh`만 사용한다. 기본값은 `127.0.0.1:8765`이며, `--host`와 `--port`로 명시적으로 바꿀 수 있다. loopback 이외의 주소에 바인딩하려면 `.env`에서 `MSW_LAN_ACCESS=true`와 32자 이상의 `MSW_API_TOKEN`, `MSW_ADMIN_TOKEN`을 함께 설정해야 한다. 진단 원본과 증적은 민감할 수 있으므로 별도 인증 없이 LAN이나 인터넷에 노출하지 않는다.

### Docker Mock 데모

Docker는 하드웨어 단말·ADB·Frida Server 접근을 대신하지 않으며, **Mock 데모와 웹 UI를 안전하게 검토하는 용도**로 제공된다.

```bash
docker compose up -d --build
```

Compose 구성은 호스트의 `127.0.0.1:8765`에만 포트를 공개하고 `./data`를 컨테이너의 영속 데이터 디렉터리로 연결한다. 프로젝트 `.env` 전체를 컨테이너에 전달하지 않으며 Docker UI 접근에 필요한 bridge 허용은 loopback Host 요청으로 제한한다. 최종 이미지에는 Frida JavaScript 승인에 필요한 Node.js 구문 검사기가 포함된다. 컨테이너 상태는 `http://127.0.0.1:8765/healthz`에서 확인할 수 있다. `docker run -p 8765:8765`처럼 모든 네트워크 인터페이스에 포트를 노출하는 명령은 사용하지 않는다.

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
11. 승인자는 전체 코드·적용 대상·위험도를 명시적으로 검토해야 하며, 브라우저가 전송한 현재 코드 SHA-256이 서버에서 재계산한 해시와 일치할 때만 승인된다. 내용이 변경되면 재승인이 필요하다.
12. 승인된 통제 검증 모드의 동의·승인 범위는 외부 AI 전송에서 제외하며 로컬 증적으로만 보존한다.
13. 취약점 분석 AI에는 선택한 국내 프로필의 ID·판정 조건과 현재 Run 증적 목록을 제공한다. AI가 추천한 ID는 `needs_review`로만 연결하며 필수 재현 증적 없이는 확정하지 않는다.
14. 보안통제 우회 AI는 `security_bypass_preparation`에서 안전 일시정지된 Run의 제한된 정적 신호·로그만 사용한다. 서버가 결과를 `high`와 `pending_approval`로 강제하고 Run별 호출 이력을 남긴다.
15. 실제 단말이 없어도 앱 분석 기준선에서 AI 사전 진단을 실행할 수 있다. 결과는 앱 SHA-256과 선택 프로필에 고정하고 모두 `needs_review`로 저장한다.
16. Run의 AI 증적 우선순위는 확정·양호·해당없음 항목을 제외하고 미판정 항목만 정렬한다. 승인·범위·판정 원장은 AI 입력에서 제외하며, 추천 ID는 서버의 로컬 증적 정책을 통과해야 화면에 표시된다.
16. 정적 신호로 만든 우회 후보는 대상 앱 ID에 묶는다. 다른 앱의 Run에서는 승인·실행할 수 없고, 실제 성공 여부는 추후 Live 단말 증적으로만 판정한다.

NVIDIA 연동은 OpenAI 호환 `POST /v1/chat/completions`, Claude 연동은 Messages `POST /v1/messages`와 JSON Schema `output_config`를 사용한다.

## 승인된 통제 검증 모드

루팅·탈옥·후킹이 가능한 단말에서 앱의 탐지·제한·증적 수집 동작을 확인해야 할 때는 **Live 진단의 승인된 통제 검증 모드**를 사용할 수 있다. 이 모드는 기본적으로 꺼져 있으며, Mock 프로젝트에서는 사용할 수 없다.

활성화하려면 고객사 또는 앱 소유자의 승인 참조와 승인자, 승인 만료 시각, 현재 선택한 테스트 단말, 비밀번호가 아닌 테스트 계정 참조, 허용 테스트 서버, 상세 범위와 세 가지 확인을 모두 입력해야 한다. 서버는 시간대가 포함된 만료 시각과 호스트 형식을 검증하고 현재 단말 ID를 승인 범위에 고정한 뒤 `approval_record` 증적으로 보존한다.

허용 서버는 `api.test.example`, `*.sandbox.example`, `192.0.2.15`처럼 호스트·IP·하위 도메인 와일드카드로 입력한다. 단일 `*`, URL 경로와 쿼리는 허용하지 않는다. 이 모드에서 mitmproxy는 허용목록 밖 목적지를 upstream 전송 전에 HTTP 451로 차단하고 차단 흐름을 원본 증적으로 남긴다. Burp/Fiddler Import를 포함해 범위 밖 흐름이 식별되면 이후 자동 네트워크 테스트와 AI 판정을 진행하지 않고 Run을 `manual_required`로 종료한다. 집행 결과는 `control_scope_enforcement` 증적과 Run 옵션에 보존하며 승인 원장과 함께 외부 AI 컨텍스트에서 제외한다.

> 이 모드는 보안 통제를 자동으로 무력화하지 않는다. 운영 계정·실제 고객 데이터에 접근하지 않으며, 승인 정보는 외부 AI 컨텍스트에 포함하지 않는다. 승인 만료·단말 불일치·범위 밖 목적지는 `manual_required`로 전환한다. 루팅·탈옥 탐지 우회는 아래의 별도 코드 검토와 1회 승인 경계를 거친 경우에만 실행한다.

### 승인형 루팅·탈옥 탐지 우회

루팅 Android 또는 탈옥 iOS에서 대상 앱이 진단 시작 자체를 차단할 때 사용할 수 있도록 다음 고위험 내장 Frida 스크립트를 제공한다.

- Android `Root Detection Bypass`: root 경로·패키지·속성·명령 실행과 RootBeer 계열 탐지를 대상 프로세스 안에서 마스킹한다.
- iOS `Jailbreak Detection Bypass`: 탈옥 경로, URL Scheme, `fork`, `DYLD_INSERT_LIBRARIES` 탐지를 대상 프로세스 안에서 마스킹한다.

진단 설정에서 **루팅·탈옥 탐지 우회 준비**를 켜면 앱 설치 후 첫 실행 전에 Run이 `safely_paused`로 전환된다. Frida 라이브러리에서 전체 코드·대상·위험도를 확인하고 현재 SHA-256을 승인한 뒤, 해당 Run에 Spawn 방식으로 1회 실행하고 진단을 재개한다. 승인 토큰은 프로젝트·Run·단말·대상 앱·스크립트에 묶이며 5분 안에 한 번만 사용할 수 있다. Live 실행에는 유효한 승인 통제 검증 범위가 추가로 필요하다. 우회 스크립트와 lifecycle 결과는 로컬 `frida_script` 증적으로 보존되지만, 그 자체만으로 취약점을 확정하지 않고 앱 실행·화면·로그 등 기준별 필수 재현 증적과 함께 판정한다.

내장 스크립트가 대상 보안 솔루션과 맞지 않으면 같은 일시정지 Run에서 **AI 후보 생성 → 보안솔루션 우회 분석**을 사용할 수 있다. 서버가 현재 앱의 루팅·탈옥·Frida·디버거·무결성 관련 정적 신호와 제한된 Run 증적만 선택하며, 승인 범위와 원본 파일은 AI에 보내지 않는다. 생성 후보는 Android `Root Detection Bypass` 또는 iOS `Jailbreak Detection Bypass`, 위험도 `high`, 승인 대기로 고정된다. AI 결과가 곧 우회 성공이나 취약 판정을 뜻하지 않는다.

실제 단말 Run이 아직 없으면 등록된 APK·IPA의 정적 신호만 사용해 사전 후보를 만들 수 있다. 이 후보에는 `target_app_id`가 저장되며 다른 앱에는 적용할 수 없다. 실행은 이후 동일 앱의 `security_bypass_preparation` 안전 일시정지와 기존 SHA-256·5분 1회 승인 경계를 모두 통과해야 한다.

## 승인형 딥링크·외부 노출 컴포넌트 검증

Live Run을 `safely_paused` 상태로 만든 뒤 **외부 진입 검증 원장**에서 정적 분석 후보를 검토할 수 있다. 클라이언트는 임의 Intent, URI, 컴포넌트 이름을 입력하지 않으며 서버가 현재 활성 분석 결과에서 후보 ID를 다시 계산한다. 승인 토큰은 프로젝트·Run·단말·후보 ID에 묶여 5분 안에 한 번만 사용할 수 있다.

Android의 Manifest 딥링크와 외부 노출 Activity/Activity Alias만 승인형 호출을 지원한다. 딥링크는 대상 패키지로 한정한다. Service, Receiver, Provider와 iOS 후보는 상태 변경·임의 데이터 접근 가능성 때문에 `manual_required`로 유지한다. 호출 전 화면을 확보하지 못하면 실행하지 않으며, 성공 여부와 관계없이 호출 전·후 화면, 명령 결과와 로그를 로컬 원본 증적으로 저장해 기존 정적 Finding에 연결한다. 외부 진입 성공은 취약점 영향 확정이 아니라 접근 가능 신호이므로 민감 기능·인증 우회 영향은 별도로 판정한다.

Live 실행에는 승인된 통제 검증 범위가 활성 상태여야 한다. Mock에서는 같은 승인·증적 흐름을 `synthetic=true`로만 재현한다.

## 승인형 UI 동작·읽기 전용 API 재현

진단 설정에서 **승인 후보에서 자동 일시정지**를 선택하면 자동 탐색 중 현재 화면의 중위험 `tap` 후보 또는 네트워크 분석 후 Live `GET/HEAD` 후보가 생성된 안전 지점에서 Run을 멈춘다. 승인 토큰은 프로젝트·Run·단말·후보 ID에 묶여 5분 안에 한 번만 사용할 수 있다.

- UI 동작은 서버가 실행 직전 현재 package, UI fingerprint, element ID와 위험도를 다시 계산한다. `medium` tap만 실행하며 high·blocked·파괴적 동작, 임의 좌표·텍스트 입력은 계속 `manual_required`다. 전·후 화면과 UI Tree, 명령 결과를 원본 증적으로 보존한다.
- Live API 재현은 현재 Run의 원본 ProxyFlow에서 다시 계산한 **본문 없는 GET/HEAD**만 허용한다. 승인된 서버 host를 재검증하고 DNS 주소와 실제 peer IP를 고정하며, 환경 프록시와 redirect를 사용하지 않고 응답을 1 MiB로 제한한다. 원본·재현 응답 구조는 Response Comparator로 비교한다.
- POST·PUT·PATCH·DELETE, 업로드, Object 경계 변경은 승인 후에도 자동 재전송하지 않는다. 승인 범위 증적은 외부 AI 컨텍스트에서 제외하고, 결과 증적을 외부 AI에 사용할 때는 기존 구조적 마스킹 정책을 적용한다.


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

각 스크립트는 플랫폼, 카테고리, 대상 프레임워크, 적용 조건, 위험도, 승인 상태, 구문 상태, 성공·실패 횟수를 저장한다. 자동 선택 가능한 내장 스크립트는 관찰용이며, 별도 루팅·탈옥 탐지 우회 스크립트는 `high`라서 자동 선택되지 않는다.

사용자·AI 후보는:

1. `pending_approval`로 저장
2. Node.js `--check` 구문 검사
3. 사용자 승인
4. 승인된 스크립트만 Spawn·Attach 또는 Mock 실행
5. 실행 명령, 전체 스크립트, 메시지와 오류를 증적으로 저장

스크립트 화면의 AI 후보 생성기는 실패 수정·관찰·보안솔루션 우회 분석 목적을 분리한다. 프로젝트의 외부 전송 정책과 마스킹을 적용하고 NVIDIA 실패 시 Claude로 fallback한다. Mock Provider로 외부 전송 없는 승인 흐름도 검증할 수 있다. 보안솔루션 우회 목적은 안전 일시정지된 현재 Run 증적에 고정되며 결과를 고위험 승인 대기로만 저장한다. 어떤 AI 후보도 자동 실행하지 않는다.

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

권한 보호가 없는 Android 외부 노출 컴포넌트는 컴포넌트별 정적 Finding으로 생성한다. 인증서 고정, 루팅·탈옥, Frida·후킹, 안티 디버깅 신호는 일반 취약점과 분리된 모바일 보안통제 검증 대상으로 표시한다. 정적 문자열만으로 실제 통제 동작이나 우회 가능성을 확정하지 않으며, 실제 단말의 화면·로그·프로세스·네트워크 증적을 추가해야 한다.

진단 실행의 발견항목 원장은 AI 판정뿐 아니라 선택 앱의 정적 Finding도 함께 보여준다. 따라서 AI가 비활성화되거나 외부 AI 전송이 허용되지 않은 프로젝트에서도 정적 고신뢰도 결과와 동적 재검증 후보가 사라지지 않는다.

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
- 승인 통제 검증 전
- 승인 통제 검증 후
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
- `/api/runs/{id}/component-candidates`, `/api/runs/{id}/component-candidates/{candidate-id}/verify`
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
- 고위험 루팅·탈옥 탐지 우회의 자동 선택 차단, 첫 실행 전 Spawn·1회 승인
- 양호 판정의 무증적 저장과 취약 확정 전용 증적 원장
- 분석기 원시 결과·MASTG 커버리지 저장
- 고위험 objection/drozer 작업 승인 차단
- Mock 업로드 → 진단 → 증적 → 발견항목 → HTML 전체 흐름

## Docker 선택 실행

Docker는 Mock 데모와 웹 UI 용도다. USB ADB·Windows Fiddler·로컬 Frida 접근은 Windows 직접 실행을 권장한다.

```powershell
docker compose up -d --build
```

## 프로젝트 구조

```text
backend/app/
├─ api/              # REST·WebSocket
├─ analyzers/        # APK·IPA 정적 분석
├─ catalog/          # 국내 2종 진단 기준·MASTG 보조 원장
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
├─ frida/            # 저위험 관찰 + 승인형 루팅·탈옥 탐지 우회
└─ mitm_capture_addon.py
tests/
docs/
```

상세 구현 계획은 [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md), OSS 통합·라이선스 경계는 [docs/OSS_INTEGRATIONS.md](docs/OSS_INTEGRATIONS.md)를 참고한다.

## 남은 확장 영역

- 제조사 보안통제별 탐지·차단 관찰 규칙과 공식 테스트 정책 Adapter
- 실제 제조사별 Android 보안 솔루션/키패드 전용 Adapter
- 장시간 Logcat·화면 녹화의 스트리밍 제어 UI
- Fiddler/Burp 프로세스 API 자동 연동
- DB/SharedPreferences/Keychain 구조화 뷰어
- Android external storage·Clipboard 귀속·FLAG_SECURE/background snapshot 검증
- 조직용 사용자 인증·권한·감사 로그(현재는 loopback 단일 사용자)
