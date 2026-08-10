from __future__ import annotations

import re

from .models import NavigationCandidate, UIElement, UIState


class NavigationRiskPolicy:
    """Local allowlist-first policy for deterministic UI exploration."""

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
    SAFE_HINTS = (
        "정보",
        "소개",
        "도움말",
        "공지",
        "설정",
        "보안",
        "프로필",
        "계정",
        "상세",
        "목록",
        "about",
        "help",
        "settings",
        "security",
        "profile",
        "account",
        "details",
        "list",
    )

    @staticmethod
    def _material(element: UIElement) -> str:
        return " ".join(
            [element.text, element.content_desc, element.resource_id, element.class_name]
        ).casefold()

    def classify(self, element: UIElement, target_package: str) -> NavigationCandidate:
        material = self._material(element)
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
        return NavigationCandidate(
            "tap",
            element.element_id,
            element.label or "unlabelled control",
            "low",
            "현재 UI Tree에 존재하는 읽기·화면 이동 후보입니다.",
            False,
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
