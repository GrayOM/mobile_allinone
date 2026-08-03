# Mobile Security Workbench 구현 계획

## 목표

Windows 10/11에서 브라우저로 사용하는 로컬 모바일 보안 진단 작업대다. Android를 우선 지원하고, 실제 도구가 없을 때도 Mock Device·Proxy·AI로 업로드부터 증적 HTML 생성까지 전 과정을 실행한다.

## 아키텍처

```text
Browser (React)
  ├─ REST: 프로젝트, 설정, 파일, 발견항목, 증적
  └─ WebSocket: 실행 단계, 로그, 패킷, AI 상태
          │
FastAPI ──┼─ DiagnosticOrchestrator
          │    ├─ Analyzer Federation
          │    │    └─ Native / Androguard / APKiD / Semgrep / MobSF
          │    ├─ DeviceAdapter (Android / iOS / Mock)
          │    ├─ FridaRunner + ScriptLibrary
          │    ├─ ProxyAdapter (mitmproxy / Fiddler / Burp / Mock)
          │    ├─ AIProviderChain (NVIDIA → Claude → 명시적 오류)
          │    ├─ RuntimeAdapter (objection / drozer)
          │    ├─ MASTG Control Ledger
          │    └─ EvidenceService + HTML renderer
          └─ SQLite + 프로젝트별 파일 저장소
```

## 상태 원칙

외부 기능은 성공 여부를 숨기지 않고 다음 상태를 반환한다.

- `available`: 현재 실행 가능
- `not_configured`: 실행 파일, API 키 또는 연결 정보가 없음
- `unsupported`: 현재 플랫폼/Adapter에서 지원하지 않음
- `manual_required`: 자동화하지 않고 사용자의 수동 절차가 필요
- `failed`: 실행을 시도했지만 실패

## 단계

1. FastAPI/React 최소 실행 골격과 설정 로더
2. SQLite 모델, 프로젝트와 업로드 API
3. APK/IPA 구조 분석과 도구별 원문·fingerprint 상관분석
4. ADB/iOS/Mock Device Adapter
5. Frida 스크립트 라이브러리와 실행·검증
6. mitmproxy/수동 프록시/Mock Proxy Adapter
7. NVIDIA/Claude/Mock AI와 JSON Schema 검증·마스킹
8. 진단 오케스트레이터, WebSocket, 증적 타임라인
9. 실사용 대시보드와 Mock E2E 데모
10. 테스트, Windows 설치/실행 스크립트, 운영 문서
11. OSS 분석·런타임 Adapter와 MASTG 통제 커버리지

## 디렉터리

```text
backend/app/
  api/ analyzers/ catalog/ devices/ frida/ proxy/ ai/
  evidence/ orchestration/ runtime/ database/
frontend/src/
rules/semgrep/ scripts/frida/
tests/ samples/ docs/
```

## MVP 경계

- Android ADB 동작과 mitmproxy 수집은 도구가 설치된 경우 실제 실행한다.
- APK 바이너리 Manifest는 기본 Androguard와 선택 apktool/aapt 결과를 결합한다. 어느 도구가 실패해도 가능한 분석을 계속한다.
- iOS 탐색·앱·로그·스크린샷은 pymobiledevice3/libimobiledevice/SSH 중 설정된 Adapter를 사용한다. 자동 서명·재서명은 Windows에서 `manual_required`다.
- Fiddler/Burp는 설정과 수동 연동 안내, HAR/JSON 가져오기 경로를 제공한다.
- AI 생성 Frida 스크립트는 구문 검사 후 `pending_approval`로 저장하며 자동 실행하지 않는다.
