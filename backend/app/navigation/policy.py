from __future__ import annotations

import re

from .models import NavigationCandidate, UIElement, UIState


class NavigationRiskPolicy:
    """Default-deny policy for deterministic, in-app UI exploration."""

    BLOCKED_TERMS = (
        "결제",
        "송금",
        "이체",
        "구매",
        "주문 확정",
        "탈퇴",
        "계정 삭제",
        "데이터 삭제",
        "삭제하기",
        "발송",
        "보내기",
        "전화",
        "공유",
        "개인정보 변경",
        "비밀번호 변경",
        "생체",
        "시스템 설정",
        "pay",
        "payment",
        "transfer",
        "purchase",
        "buy now",
        "place order",
        "delete account",
        "delete data",
        "send message",
        "send email",
        "call",
        "share",
        "change password",
        "biometric",
        "system settings",
    )
    LOGIN_TERMS = (
        "로그인",
        "로그아웃",
        "로그 아웃",
        "회원가입",
        "인증번호",
        "login",
        "log in",
        "sign in",
        "sign up",
        "logout",
        "log out",
        "otp",
    )
    EXTERNAL_INTENT_TERMS = (
        "고객센터",
        "문의하기",
        "전화 걸기",
        "전화하기",
        "지도",
        "길찾기",
        "위치 보기",
        "브라우저",
        "웹사이트",
        "웹으로 보기",
        "외부 링크",
        "링크 열기",
        "설정 열기",
        "설정으로 이동",
        "앱 설정",
        "권한 설정",
        "support center",
        "contact support",
        "website",
        "open external",
        "open browser",
        "open in browser",
        "open map",
        "directions",
        "external link",
        "open settings",
        "app settings",
        "permission settings",
    )
    CONFIRMATION_TERMS = (
        "확인",
        "저장",
        "등록",
        "신청",
        "예약",
        "완료",
        "동의",
        "허용",
        "제출",
        "적용",
        "구독",
        "confirm",
        "save",
        "register",
        "apply",
        "reserve",
        "book",
        "complete",
        "agree",
        "allow",
        "submit",
        "subscribe",
    )
    SAFE_HINTS = (
        "정보",
        "소개",
        "도움말",
        "공지",
        "보안",
        "프로필",
        "상세",
        "목록",
        "약관",
        "정책",
        "faq",
        "about",
        "help",
        "security",
        "profile",
        "details",
        "list",
        "terms",
        "policy",
    )
    SAFE_NAVIGATION_CLASSES = {
        "textview",
        "viewgroup",
        "linearlayout",
        "relativelayout",
        "framelayout",
        "constraintlayout",
        "tabview",
        "tab",
        "bottomnavigationitemview",
        "navigationmenuitemview",
    }
    APPROVAL_CONTROL_CLASSES = {
        "button",
        "imagebutton",
        "switch",
        "switchcompat",
        "checkbox",
        "radiobutton",
        "togglebutton",
        "seekbar",
        "spinner",
    }
    SAFE_RESOURCE_TERMS = (
        "detail",
        "details",
        "list",
        "item",
        "tab",
        "menu",
        "about",
        "help",
        "notice",
        "profile",
        "security_info",
        "certificate_info",
    )

    @staticmethod
    def _material(element: UIElement) -> str:
        return " ".join(
            [element.text, element.content_desc, element.resource_id, element.class_name]
        ).casefold()

    def classify(self, element: UIElement, target_package: str) -> NavigationCandidate:
        material = self._material(element)
        label = element.label.strip()
        class_name = element.class_name.rsplit(".", 1)[-1].casefold()
        if element.package and target_package and element.package != target_package:
            return NavigationCandidate(
                "tap",
                element.element_id,
                element.label,
                "blocked",
                "대상 앱 패키지 밖의 UI 요소입니다.",
                True,
            )
        if element.password or "edittext" in element.class_name.casefold():
            return NavigationCandidate(
                "tap",
                element.element_id,
                element.label,
                "medium",
                "자격증명·개인정보 입력은 사용자 수동 단계로 남깁니다.",
                True,
            )
        if any(term in material for term in self.BLOCKED_TERMS):
            return NavigationCandidate(
                "tap",
                element.element_id,
                element.label,
                "high",
                "상태 변경 또는 외부 부작용 가능성이 있어 자동 실행을 차단했습니다.",
                True,
            )
        if any(term in material for term in self.LOGIN_TERMS):
            return NavigationCandidate(
                "tap",
                element.element_id,
                element.label,
                "medium",
                "로그인·가입·인증 동작은 사용자 확인이 필요합니다.",
                True,
            )
        if any(term in material for term in self.EXTERNAL_INTENT_TERMS):
            return NavigationCandidate(
                "tap",
                element.element_id,
                label,
                "high",
                "외부 앱·브라우저·전화·지도·시스템 화면을 열 가능성이 있어 승인이 필요합니다.",
                True,
            )
        if not label:
            return NavigationCandidate(
                "tap",
                element.element_id,
                "unlabelled control",
                "medium",
                "의도와 외부 Intent 여부를 확인할 수 없는 무라벨 요소는 자동 실행하지 않습니다.",
                True,
            )
        if (
            class_name in self.APPROVAL_CONTROL_CLASSES
            or any(term in material for term in self.CONFIRMATION_TERMS)
        ):
            return NavigationCandidate(
                "tap",
                element.element_id,
                label,
                "medium",
                "Button·토글 또는 확인/저장 계열 제어는 상태 변경 가능성이 있어 승인이 필요합니다.",
                True,
            )
        has_navigation_semantics = any(
            term in material for term in self.SAFE_HINTS
        ) or any(
            term in element.resource_id.casefold()
            for term in self.SAFE_RESOURCE_TERMS
        )
        if class_name in self.SAFE_NAVIGATION_CLASSES and has_navigation_semantics:
            return NavigationCandidate(
                "tap",
                element.element_id,
                label,
                "low",
                "검증된 탐색 클래스와 명확한 목록·탭·상세 이동 의미를 모두 만족합니다.",
                False,
            )
        return NavigationCandidate(
            "tap",
            element.element_id,
            label,
            "medium",
            "자동 탐색 allowlist에 없는 clickable 요소이므로 기본 거부했습니다.",
            True,
        )

    def candidates(self, state: UIState, target_package: str) -> list[NavigationCandidate]:
        candidates = [
            self.classify(item, target_package)
            for item in state.elements
            if item.clickable and item.enabled and item.bounds.area > 0
        ]

        def score(candidate: NavigationCandidate) -> tuple[int, str, str]:
            material = candidate.label.casefold()
            safe_hint = any(term in material for term in self.SAFE_HINTS)
            risk_order = {"low": 0, "medium": 1, "high": 2, "blocked": 3}
            return (risk_order.get(candidate.risk, 9) - int(safe_hint), material, candidate.element_id)

        unique: dict[str, NavigationCandidate] = {}
        for candidate in sorted(candidates, key=score):
            unique.setdefault(candidate.element_id, candidate)
        return list(unique.values())

    @classmethod
    def contains_dangerous_label(cls, value: str) -> bool:
        normalized = re.sub(r"\s+", " ", value.casefold()).strip()
        return any(term in normalized for term in cls.BLOCKED_TERMS)
