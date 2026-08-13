import type { Finding } from "./types";

export type FindingLane = "vulnerability" | "security_control";

const SECURITY_CONTROL_CATEGORIES = new Set([
  "app_protection",
  "anti_debugging",
  "certificate_pinning",
  "debugger_detection",
  "frida_detection",
  "integrity_signature",
  "jailbreak_detection",
  "obfuscation",
  "root_detection",
  "security_control",
]);

export function findingLane(finding: Finding): FindingLane {
  return SECURITY_CONTROL_CATEGORIES.has(finding.category)
    ? "security_control"
    : "vulnerability";
}

export function findingLaneLabel(finding: Finding): string {
  return findingLane(finding) === "security_control"
    ? "모바일 보안통제 신호"
    : "앱 취약점";
}

export function findingEvidenceLabel(finding: Finding): string {
  const isStatic = finding.source.startsWith("static:");
  if (findingLane(finding) === "security_control" && isStatic) {
    return "동적 통제 검증 필요";
  }
  if (isStatic && finding.verdict === "confirmed") return "정적 확인";
  if (isStatic) return "동적 재검증 필요";
  if (finding.verdict === "confirmed") return "실행 증적으로 확인";
  if (["candidate", "needs_review"].includes(finding.verdict)) {
    return "실행 증적 보강 필요";
  }
  return "실행 판정";
}
