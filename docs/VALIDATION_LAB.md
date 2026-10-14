# 검증 랩: 직접 만든 앱 외의 공개 연습 앱

고객 앱 없이도 Live 경로를 실기기에서 검증할 수 있도록, 의도적으로 취약하게 만든 공개 연습 앱과 이 작업대 기능의 대응을 정리한다. 모든 앱은 자체 소유 테스트 단말과 격리된 랩 네트워크에서만 실행한다. 고객 서버나 실제 계정에는 연결하지 않는다.

| 앱 | 플랫폼 | 라이선스 | 이 작업대에서 검증할 기능 |
|---|---|---|---|
| [OVAA](https://github.com/oversecured/ovaa) | Android (소스 빌드) | BSD-2-Clause | 외부 노출 컴포넌트·딥링크 후보 원장(EFI-MA-54), 하드코딩 키 Semgrep 규칙, 로그 노출(EFI-MA-49) |
| [MASTG Hacking Playground](https://github.com/OWASP/MASTG-Hacking-Playground) | Android Java/Kotlin, iOS Swift (릴리스 APK/IPA) | GPL-3.0 | MASTG 보조 원장, 정적 분석기 연합, iOS 업로드·재서명 흐름 |
| [MAS Crackmes (UnCrackable L1~L4)](https://mas.owasp.org/crackmes) | Android, iOS | MASTG 연습 자료 | 루팅·탈옥 탐지 신호, 첫 실행 전 안전 일시정지, 난독화 항목 |
| [DVIA-v2](https://github.com/prateek147/DVIA-v2) | iOS (iOS 11까지 검증) | 저장소 라이선스 확인 | 탈옥 탐지 신호, iOS 저장소·로그 항목 |

## 진행 순서

1. Mock 프로젝트에서 같은 화면 흐름을 먼저 연습한다.
2. Live 프로젝트를 만들고, 승인 통제 검증 범위에 랩 단말 ID와 랩 서버 호스트만 넣는다.
3. 앱을 업로드해 정적 원장과 점검 계획을 확인한다. iOS는 필요하면 **IPA 재서명**으로 랩 단말용 사본을 만든다.
4. Run을 실행해 화면·로그·프로세스·프록시 증적이 수집되는지 확인한다.
5. 국내 기준 원장에서 필수 증적이 충족된 항목만 취약 판정 작업으로 확정한다.

## 주의

- 2016~2018년 이후 갱신이 멈춘 앱(DIVA, InsecureBankv2 등)은 최신 Android에서 설치되지 않을 수 있다.
- 연습 앱 결과를 고객 보고서나 실제 진단 결과로 사용하지 않는다.
- 연습 앱 원본은 저장소에 커밋하지 않는다. `/test_apk/`는 `.gitignore` 대상이다.
