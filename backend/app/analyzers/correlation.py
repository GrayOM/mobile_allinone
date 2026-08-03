from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


WORD = re.compile(r"[A-Za-z0-9가-힣]{2,}")


def _tokens(value: str) -> set[str]:
    ignored = {
        "testing",
        "check",
        "점검",
        "후보",
        "탐지",
        "구현",
        "android",
        "ios",
        "analysis",
    }
    return {
        token.lower()
        for token in WORD.findall(value)
        if token.lower() not in ignored
    }


def _location_key(value: str) -> str:
    value = re.sub(r":\d+(?::\d+)?$", "", value.strip().lower())
    value = value.replace("\\", "/")
    return value.rsplit("/", 1)[-1][:180]


def _similar(left, right) -> bool:
    if left.category != right.category:
        return False
    left_location = _location_key(left.location)
    right_location = _location_key(right.location)
    if left_location and right_location and left_location == right_location:
        return True
    left_tokens = _tokens(f"{left.title} {left.rationale}")
    right_tokens = _tokens(f"{right.title} {right.rationale}")
    if not left_tokens or not right_tokens:
        return False
    overlap = len(left_tokens & right_tokens)
    return overlap >= 2 and overlap / min(len(left_tokens), len(right_tokens)) >= 0.55


@dataclass(slots=True)
class CorrelatedGroup:
    primary: object
    members: list[object] = field(default_factory=list)


def correlate_findings(findings: Iterable[object]) -> list[CorrelatedGroup]:
    groups: list[CorrelatedGroup] = []
    for finding in sorted(
        findings, key=lambda item: float(getattr(item, "confidence", 0)), reverse=True
    ):
        matched = next(
            (
                group
                for group in groups
                if any(_similar(finding, member) for member in group.members)
            ),
            None,
        )
        if matched:
            matched.members.append(finding)
        else:
            groups.append(CorrelatedGroup(primary=finding, members=[finding]))
    return groups

