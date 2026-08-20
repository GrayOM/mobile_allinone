# 국내 모바일 앱 취약점 판정 원장

## 기준 프로필

| 프로필 값 | 화면 이름 | 항목 수 | 로컬 ID |
|---|---|---:|---|
| `critical_infrastructure` | 주요정보통신기반시설 | 27 | `CII-MA-01` ~ `CII-MA-27` |
| `electronic_financial` | 전자금융기반시설 | 56 | `EFI-MA-01` ~ `EFI-MA-56` |

항목명과 진단 기준은 사용자가 제공한 두 DOCX 권고안에서 실행 정책에 필요한 부분을 요약한 것이다. 원문 전체를 복제하지 않는다. 프로젝트 생성 시 한 프로필을 선택하며 앱 또는 진단 이력이 생긴 뒤에는 변경할 수 없다.

## 판정 규칙

`ControlTest`는 `not_tested`, `needs_review`, `confirmed`, `not_vulnerable`, `not_applicable` 판정을 보존한다.

- 정적 분석 신호는 후보와 `needs_review`만 만들며 단독으로 `confirmed`가 될 수 없다.
- 자동 확정은 같은 Run의 재현 결과와 해당 항목의 필수 증적 그룹이 모두 연결된 경우에만 허용한다.
- 승인 수동 `confirmed` 판정은 원본 첨부 증적, 검토자, 기준 충족 여부, 판정 요약을 변경 불가능한 `assessment_attestation` 증적으로 남긴다.
- 수동 `confirmed`는 필수 증적이 없으면 API가 422로 거부한다. `not_vulnerable`과 `not_applicable`은 상태·검토 메타데이터만 기록하며 증적을 요구하거나 생성하지 않는다.
- 국내 기준 판정 원장과 승인 기록은 외부 AI 컨텍스트에서 제외한다.
- AI에는 선택한 프로필의 로컬 ID·판정 조건과 승인 기록을 제외한 현재 Run 증적만 제공한다. 응답의 ID는 서버가 현재 프로필과 대조하며, 유효한 추천도 `needs_review`로만 연결한다.
- Mock 판정은 `synthetic=true`를 유지하며 Live 판정과 합치지 않는다.

## 실행 매트릭스

83개 항목은 현재 구현 가능 범위와 외부 준비 조건을 다음 레일로 분리한다.

- `ready_now`: APK·IPA 정적 분석, OSS 상관분석, AI 정적 사전 분류를 지금 수행할 수 있다.
- `device_required`: 실제 Android/iOS 화면·프로세스·저장소·메모리·런타임 증적이 필요하다. 단말 없이 성공 처리하지 않는다.
- `server_scope_required`: 승인된 테스트 서버·계정 범위에서 인증·인가·거래·세션을 재현해야 한다.
- `manual_review`: 자동 상태 변경 없이 문서 기준과 외부 원본 증적을 검토한다.

`GET /api/assessment/execution-matrix`는 두 프로필 전체를, `?profile=<profile>`은 선택한 기준만 반환한다. 각 행에는 단말·서버·테스트 계정·상태 변경 필요 여부와 현재 가능한 준비 작업이 포함된다.

앱 업로드·재분석의 활성화 트랜잭션은 선택 프로필의 앱별 점검 계획을 함께 생성한다. 계획은 활성 분석의 앱 ID·SHA-256·프로필에 고정되며 다음 상태를 사용한다.

- `candidate_detected`: 정적 Finding·통제 신호·문자열 또는 AI 사전 매핑 후보가 있다. 판정은 `needs_review`다.
- `review_ready`: 정적 산출물이 준비되어 문서 기준의 전문가 검토를 바로 시작할 수 있다.
- `screened_no_candidate`: 정적 선별에서 후보를 찾지 못했지만 양호 판정으로 바꾸지 않는다.
- `waiting_device`: 실제 화면·프로세스·저장소·메모리 등 단말 증적을 기다린다.
- `waiting_server_scope`: 허용 테스트 서버와 필요한 경우 테스트 계정 참조를 기다린다.
- `waiting_manual_review`: 승인 검토자와 외부 원본 증적을 기다린다.

`GET /api/apps/{app-id}/assessment/plan`은 현재 계획을 반환하고 이전 앱은 필요할 때 안전하게 backfill한다. `POST /api/apps/{app-id}/assessment/plan/refresh`는 현재 활성 분석 결과로 계획과 앱 기준선의 선별 상태를 다시 계산한다. 어느 경로도 `confirmed`, `not_vulnerable`, `not_applicable`을 자동 생성하지 않는다.

`POST /api/apps/{app-id}/ai/triage`는 앱 정적 결과와 현재 프로필 ID를 AI에 전달해 사전 후보를 만든다. 승인 범위는 제외하고 외부 전송 정책과 마스킹을 적용한다. 결과는 앱 SHA-256에 고정되며 `needs_review` 이외의 판정으로 저장하지 않는다.

루팅·탈옥 항목(`CII-MA-22`, `EFI-MA-07`)의 자동 취약 확정에는 다음 세 가지가 필요하다.

1. 단말의 루팅·탈옥 상태를 보여 주는 `device_state`
2. 대상 package 또는 Bundle ID 프로세스가 실제 실행 중임을 보여 주는 `process_state`
3. 서비스 이용 화면을 보여 주는 `screenshot`

보안 솔루션이 실행을 차단하면 진단 설정의 **루팅·탈옥 탐지 우회 준비**에서 첫 앱 실행 전에 일시정지한다. Android Root Detection Bypass 또는 iOS Jailbreak Detection Bypass의 전체 코드와 SHA-256을 검토하고, 승인 범위에 고정된 5분 만료 1회 토큰으로 Spawn 실행한다. 실행 결과의 `frida_script` 증적은 앱 실행·프로세스·화면 증적과 함께 취약 확정에 연결될 수 있다. 이 고위험 스크립트는 자동 선택·자동 실행되지 않으며 제조사별 RASP·보안 키패드 우회는 아직 범용 지원하지 않는다.

대상별 Hook 분석이 필요하면 같은 준비 단계에서 AI 우회 후보를 만들 수 있다. 서버가 정적 보안통제 신호와 제한된 Run 로그·증적만 선택하고, 생성 결과의 플랫폼·우회 범주·`high` 위험도를 다시 고정한다. 후보는 구문 검사 후 `pending_approval`로 저장되며 전체 코드와 현재 SHA-256 검토 없이는 실행할 수 없다.

## 실행과 증적

Run 종료 전에 선택 프로필 전체를 평가한다. 취약 확정 항목이 있을 때만 해당 항목과 연결 증적을 담은 `vulnerability_assessment` JSON을 만들며, 양호·해당없음 항목은 여기에 포함하지 않는다. Live Run에서 판정되지 않은 항목은 품질 Gap으로 남아 `completed_with_gaps`가 된다. 승인 수동 판정으로 모든 Gap이 해소되면 Run 상태를 다시 계산한다.

`POST /api/runs/{run-id}/report/docx`와 동일 경로의 GET은 취약 확정 항목 전용 DOCX를 생성·다운로드한다. 보고서에는 확정 항목의 판정 근거, 기준, 재현 절차, 마스킹한 인라인 증적 요약, 화면 이미지와 조치 권고만 들어간다. 양호·해당없음·미확정 항목은 포함하지 않으며 취약 확정이 0건이면 생성하지 않는다.

주요 API:

```text
GET  /api/assessment/profiles
GET  /api/coverage?app_id=<id>&standard=<profile>
GET  /api/coverage?run_id=<id>&standard=<profile>
POST /api/assessment-controls/{control-test-id}/evidence
POST /api/assessment-controls/{control-test-id}/record
GET  /api/assessment/execution-matrix
GET  /api/apps/{app-id}/assessment/plan
POST /api/apps/{app-id}/assessment/plan/refresh
POST /api/apps/{app-id}/ai/triage
POST /api/runs/{run-id}/report/docx
GET  /api/runs/{run-id}/report/docx
```

수동 증적 첨부는 PNG, JPEG, TXT, LOG, JSON, XML, HAR만 허용하며 파일 크기와 SHA-256을 기록한다. 상태 변경·파괴적 점검은 자동화하지 않고 승인된 범위에서 별도 수동 증적으로 판정한다.
