from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree


BOUNDS_PATTERN = re.compile(r"^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$")


def _bool(value: str | None) -> bool:
    return str(value).lower() == "true"


def _clean(value: str | None, *, limit: int = 512) -> str:
    return " ".join((value or "").split())[:limit]


@dataclass(slots=True, frozen=True)
class Bounds:
    left: int
    top: int
    right: int
    bottom: int

    @classmethod
    def parse(cls, value: str | None) -> "Bounds":
        match = BOUNDS_PATTERN.fullmatch(value or "")
        if not match:
            return cls(0, 0, 0, 0)
        left, top, right, bottom = (int(item) for item in match.groups())
        if right < left or bottom < top:
            return cls(0, 0, 0, 0)
        return cls(left, top, right, bottom)

    @property
    def center(self) -> tuple[int, int]:
        return ((self.left + self.right) // 2, (self.top + self.bottom) // 2)

    @property
    def area(self) -> int:
        return max(0, self.right - self.left) * max(0, self.bottom - self.top)

    def to_list(self) -> list[int]:
        return [self.left, self.top, self.right, self.bottom]


@dataclass(slots=True)
class UIElement:
    element_id: str
    text: str
    content_desc: str
    resource_id: str
    class_name: str
    package: str
    bounds: Bounds
    clickable: bool
    enabled: bool
    scrollable: bool
    password: bool
    selected: bool
    checked: bool
    index: int
    tree_path: str

    @classmethod
    def from_attributes(
        cls, attributes: dict[str, str], index: int, tree_path: str
    ) -> "UIElement":
        bounds = Bounds.parse(attributes.get("bounds"))
        password = _bool(attributes.get("password"))
        raw_text = _clean(attributes.get("text"))
        text = "••••" if password and raw_text else raw_text
        signature = "\x1f".join(
            [
                _clean(attributes.get("resource-id")),
                _clean(attributes.get("class")),
                _clean(attributes.get("content-desc")),
                str(bounds.to_list()),
                tree_path,
            ]
        )
        element_id = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:20]
        return cls(
            element_id=element_id,
            text=text,
            content_desc=_clean(attributes.get("content-desc")),
            resource_id=_clean(attributes.get("resource-id")),
            class_name=_clean(attributes.get("class")),
            package=_clean(attributes.get("package")),
            bounds=bounds,
            clickable=_bool(attributes.get("clickable")),
            enabled=_bool(attributes.get("enabled")),
            scrollable=_bool(attributes.get("scrollable")),
            password=password,
            selected=_bool(attributes.get("selected")),
            checked=_bool(attributes.get("checked")),
            index=index,
            tree_path=tree_path,
        )

    @property
    def label(self) -> str:
        return self.text or self.content_desc or self.resource_id.rsplit("/", 1)[-1]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["bounds"] = self.bounds.to_list()
        return data


@dataclass(slots=True)
class UIState:
    package: str
    activity: str
    window: str
    elements: list[UIElement]
    raw_xml: str = field(repr=False)
    captured_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    fingerprint: str = ""
    structural_fingerprint: str = ""
    content_fingerprint: str = ""
    text_hash: str = ""

    def __post_init__(self) -> None:
        text_material = "\x1f".join(
            item.text or item.content_desc for item in self.elements if item.text or item.content_desc
        )
        self.text_hash = hashlib.sha256(text_material.encode("utf-8")).hexdigest()
        structural = {
            "package": self.package,
            "activity": self.activity,
            "elements": sorted(
                [{
                    "tree_path": item.tree_path,
                    "resource_id": item.resource_id,
                    "class": item.class_name,
                    "clickable": item.clickable,
                    "scrollable": item.scrollable,
                    "password": item.password,
                } for item in self.elements],
                key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False),
            ),
        }
        content = {
            "structure": structural,
            "elements": sorted(
                [{
                    "tree_path": item.tree_path,
                    "resource_id": item.resource_id,
                    "text": item.text,
                    "content_desc": item.content_desc,
                    "bounds": item.bounds.to_list(),
                    "enabled": item.enabled,
                    "selected": item.selected,
                    "checked": item.checked,
                } for item in self.elements],
                key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False),
            ),
        }
        structural_encoded = json.dumps(
            structural, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        content_encoded = json.dumps(
            content, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.structural_fingerprint = hashlib.sha256(structural_encoded).hexdigest()
        self.content_fingerprint = hashlib.sha256(content_encoded).hexdigest()
        # Compatibility alias: traversal uses the stable structural identity.
        self.fingerprint = self.structural_fingerprint

    @classmethod
    def from_xml(
        cls,
        raw_xml: str,
        *,
        package: str = "",
        activity: str = "",
        window: str = "",
    ) -> "UIState":
        if len(raw_xml.encode("utf-8")) > 4 * 1024 * 1024:
            raise ValueError("UI hierarchy exceeds the 4 MiB safety limit")
        upper = raw_xml[:4096].upper()
        if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
            raise ValueError("UI hierarchy declarations are not allowed")
        try:
            root = ElementTree.fromstring(raw_xml)
        except ElementTree.ParseError as exc:
            raise ValueError(f"UI hierarchy XML is invalid: {exc}") from exc
        elements: list[UIElement] = []

        def walk(parent: ElementTree.Element, parent_path: str) -> None:
            for node in parent:
                if node.tag != "node":
                    walk(node, parent_path)
                    continue
                attributes = dict(node.attrib)
                resource = _clean(attributes.get("resource-id"))
                class_name = _clean(attributes.get("class"))
                segment = resource or class_name or "node"
                tree_path = f"{parent_path}/{segment}"[:2048]
                elements.append(
                    UIElement.from_attributes(attributes, len(elements), tree_path)
                )
                walk(node, tree_path)

        walk(root, "hierarchy")
        inferred_package = package or next(
            (item.package for item in elements if item.package), ""
        )
        return cls(
            package=inferred_package,
            activity=activity,
            window=window,
            elements=elements,
            raw_xml=raw_xml,
        )

    @property
    def visible_text(self) -> list[str]:
        return list(
            dict.fromkeys(
                item.text or item.content_desc
                for item in self.elements
                if item.text or item.content_desc
            )
        )

    def element(self, element_id: str) -> UIElement | None:
        return next((item for item in self.elements if item.element_id == element_id), None)

    def to_dict(self, *, include_elements: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "fingerprint": self.fingerprint,
            "structural_fingerprint": self.structural_fingerprint,
            "content_fingerprint": self.content_fingerprint,
            "package": self.package,
            "activity": self.activity,
            "window": self.window,
            "visible_text": self.visible_text,
            "text_hash": self.text_hash,
            "captured_at": self.captured_at,
            "element_count": len(self.elements),
        }
        if include_elements:
            data["elements"] = [item.to_dict() for item in self.elements]
        return data


@dataclass(slots=True, frozen=True)
class NavigationCandidate:
    action_type: str
    element_id: str
    label: str
    risk: str
    rationale: str
    requires_approval: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class NavigationAction:
    sequence: int
    action_type: str
    element_id: str | None
    label: str
    risk: str
    source_state: str
    destination_state: str | None
    result: str
    message: str
    timestamp: str
    evidence_ids: list[str] = field(default_factory=list)
    command: str | None = None
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class NavigationLimits:
    max_states: int = 12
    max_depth: int = 4
    max_actions: int = 20
    per_screen_action_limit: int = 5
    action_timeout: float = 10.0
    repeated_state_limit: int = 2
    total_navigation_minutes: float = 2.0

    @classmethod
    def from_options(cls, options: dict[str, Any] | None) -> "NavigationLimits":
        source = options if isinstance(options, dict) else {}

        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(source.get(name, default))
            except (TypeError, ValueError):
                value = default
            return min(max(value, minimum), maximum)

        def number(name: str, default: float, minimum: float, maximum: float) -> float:
            try:
                value = float(source.get(name, default))
            except (TypeError, ValueError):
                value = default
            return min(max(value, minimum), maximum)

        return cls(
            max_states=integer("max_states", 12, 1, 100),
            max_depth=integer("max_depth", 4, 1, 20),
            max_actions=integer("max_actions", 20, 1, 200),
            per_screen_action_limit=integer("per_screen_action_limit", 5, 1, 20),
            action_timeout=number("action_timeout", 10.0, 1.0, 30.0),
            repeated_state_limit=integer("repeated_state_limit", 2, 1, 10),
            total_navigation_minutes=number(
                "total_navigation_minutes", 2.0, 0.1, 30.0
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class NavigationResult:
    status: str
    message: str
    termination_reason: str
    states: list[UIState]
    actions: list[NavigationAction]
    pending_approval: list[dict[str, Any]]
    limits: NavigationLimits
    started_at: str
    finished_at: str
    synthetic: bool = False

    def to_dict(self, *, include_elements: bool = False) -> dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message,
            "termination_reason": self.termination_reason,
            "states": [
                item.to_dict(include_elements=include_elements) for item in self.states
            ],
            "actions": [item.to_dict() for item in self.actions],
            "pending_approval": self.pending_approval,
            "limits": self.limits.to_dict(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "synthetic": self.synthetic,
            "state_count": len(self.states),
            "action_count": len(self.actions),
        }
