from enum import Enum


class StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class CapabilityStatus(StringEnum):
    AVAILABLE = "available"
    NOT_CONFIGURED = "not_configured"
    UNSUPPORTED = "unsupported"
    MANUAL_REQUIRED = "manual_required"
    FAILED = "failed"


class Platform(StringEnum):
    ANDROID = "android"
    IOS = "ios"
    MOCK_ANDROID = "mock_android"
    MOCK_IOS = "mock_ios"


class RunStatus(StringEnum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class FindingVerdict(StringEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    INFORMATIONAL = "informational"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
