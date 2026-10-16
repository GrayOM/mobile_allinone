# 모바일 보안솔루션 분석기

`security_solution_analyzer`는 APK·IPA에 포함된 앱 보호·위협 탐지·보안 키패드·무결성 증명 SDK의 정적 통합 지표를 식별한다.

## 분석 범위

- 패키지·클래스 namespace
- Android `.so`, iOS `.dylib` 네이티브 라이브러리
- iOS framework와 archive 경로
- 제품 고유 문자열

패키지·라이브러리·framework는 강한 지표, 제품 문자열은 보조 지표로 계산한다. 서로 다른 종류의 근거가 함께 발견되면 신뢰도가 올라간다. 결과에는 제품명, 제조사, 분류, 신뢰도, 원본 위치, 예상 통제 영역과 실단말 추가 확인 절차가 들어간다.

알려진 제품 시그니처가 없어도 탈옥/루팅 탐지, Frida/후킹 탐지, 무결성·디버거 탐지 중 서로 독립된 통제 그룹이 둘 이상 확인되면 `custom-in-app-protection`으로 분류한다. 이 경우 공급사와 제품은 식별 불가로 명시하며 특정 상용 솔루션으로 귀속하지 않는다.

## 출력

- `analysis_result.structure.security_solutions`: 제품별 상세 결과
- `analysis_result.structure.security_solution_analysis`: 카탈로그 버전·탐지 요약·한계
- `tool_runs`: `security_solution_analyzer` 실행 상태와 시그니처 수
- `security_solution` 범주의 info Finding: 일반 취약점과 분리된 보안통제 레인
- 앱 상세 화면 `MOBILE DEFENSE FINGERPRINT`: 신뢰도와 식별 근거

## 판정 경계

- `no_known_signature`는 보안솔루션 미적용을 의미하지 않는다.
- SDK 포함만으로 보호 기능 활성화나 정책 적용을 확정하지 않는다.
- 정적 결과로 우회 가능성이나 취약점을 확정하지 않는다.
- 최종 확인은 승인된 Live Run에서 정상 기준선, 탐지 조건, 화면·프로세스·로그 증적을 함께 수집한다.

## 시그니처 유지보수

`backend/app/analyzers/security_solutions.py`의 시그니처에는 일반적인 `security`, `shield` 같은 단독 단어를 넣지 않는다. 제품의 공식 패키지·framework·라이브러리처럼 재현 가능한 지표를 우선하고, 추가 시 Android/iOS 플랫폼 오탐과 기존 분석 결과의 하위 호환 테스트를 함께 작성한다.
