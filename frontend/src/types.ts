export type CapabilityStatus =
  | "available"
  | "not_configured"
  | "unsupported"
  | "manual_required"
  | "failed";

export interface Project {
  id: string;
  name: string;
  description: string;
  ai_enabled: boolean;
  external_ai_allowed: boolean;
  external_analyzer_allowed: boolean;
  external_analyzer_approved_by: string | null;
  external_analyzer_approved_at: string | null;
  external_analyzer_destination: string | null;
  external_analyzer_addresses: string[];
  external_analyzer_certificate_sha256: string | null;
  mock_mode: boolean;
  run_mode: "mock" | "live";
  assessment_profile: "critical_infrastructure" | "electronic_financial";
  retention_days: number;
  raw_access_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AppArtifact {
  id: string;
  project_id: string;
  original_name: string;
  sha256: string;
  size_bytes: number;
  platform: string;
  app_name: string | null;
  package_name: string | null;
  version: string | null;
  analysis_status: string;
  analysis_result: Record<string, unknown> & {
    permissions?: string[];
    components?: Array<Record<string, unknown>>;
    candidates?: Array<Record<string, unknown>>;
    findings?: Array<Record<string, unknown>>;
    signals?: Record<string, Array<Record<string, string>>>;
    warnings?: string[];
    assessment_plan?: AssessmentPlan;
  };
  active_analysis_run_id: string | null;
  synthetic: boolean;
  created_at: string;
}

export interface Device {
  id: string;
  platform: string;
  model: string;
  os_version: string;
  architecture: string;
  connection: string;
  privileged: boolean | null;
  frida_status: CapabilityStatus;
  proxy_status: CapabilityStatus;
  availability: CapabilityStatus;
  capabilities: string[];
  adapter: string;
  details: Record<string, unknown>;
  synthetic: boolean;
}

export interface DiagnosticRun {
  id: string;
  project_id: string;
  app_id: string | null;
  device_id: string;
  device_adapter: string;
  proxy_adapter: string;
  run_mode: "mock" | "live";
  synthetic: boolean;
  status: string;
  current_stage: string;
  progress: number;
  options: Record<string, unknown>;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  project_id: string;
  run_id: string | null;
  title: string;
  category: string;
  platform: string;
  severity: string;
  location: string;
  verdict: string;
  confidence: number;
  rationale: string;
  reproduction: string[];
  false_positive_risk: string;
  additional_checks: string[];
  source: string;
  synthetic: boolean;
  created_at: string;
}

export interface Evidence {
  id: string;
  run_id: string;
  finding_id: string | null;
  evidence_type: string;
  title: string;
  description: string;
  sequence: number;
  file_path: string | null;
  mime_type: string | null;
  command: string | null;
  inline_data: Record<string, unknown> | unknown[] | null;
  sha256: string | null;
  synthetic: boolean;
  captured_at: string;
}

export interface ProjectDataRunInventory {
  run_id: string;
  status: string;
  created_at: string;
  retention_basis_at: string;
  expires_at: string;
  expired: boolean;
  synthetic: boolean;
  evidence_count: number;
  evidence_file_count: number;
  flow_count: number;
  finding_count: number;
  ai_invocation_count: number;
  ai_raw_response_count: number;
  has_frida_transcript: boolean;
  disk_bytes: number;
}

export interface ProjectDataInventory {
  project_id: string;
  project_name: string;
  retention_days: number;
  raw_access_enabled: boolean;
  generated_at: string;
  cutoff_at: string;
  automatic_deletion: false;
  confirmation_policy: string;
  run_count: number;
  expired_run_count: number;
  total_disk_bytes: number;
  expired_run_ids: string[];
  runs: ProjectDataRunInventory[];
}

export interface RunRawIndex {
  project_id: string;
  run_id: string;
  cache_policy: "no-store";
  sensitive_local_data: true;
  evidence: Array<{
    id: string;
    type: string;
    title: string;
    sequence: number;
    mime_type: string | null;
    sha256: string | null;
    captured_at: string;
    download_available: boolean;
    synthetic: boolean;
  }>;
  ai_invocations: Array<{
    id: string;
    provider: string;
    model: string;
    task: string;
    status: string;
    masked: boolean;
    quality_score: number | null;
    raw_response_available: boolean;
    synthetic: boolean;
    created_at: string;
  }>;
  raw_flows_endpoint: string;
}

export interface ComponentValidationCandidate {
  id: string;
  kind: "deep_link" | "exported_component";
  package_name: string;
  component_type: string;
  component_name: string | null;
  uri?: string;
  label: string;
  target: string;
  location: string;
  risk: string;
  execution_status: "approval_required" | "manual_required";
  rationale: string;
  finding_id: string | null;
  last_result: {
    status: string;
    reachable: boolean;
    evidence_id: string;
    captured_at: string;
  } | null;
}

export interface ProxyFlow {
  id: string;
  run_id: string;
  method: string;
  url: string;
  request_headers: Record<string, unknown>;
  request_body: string;
  status_code: number | null;
  response_headers: Record<string, unknown>;
  response_body: string;
  sensitive_candidates: Array<Record<string, unknown>>;
  source_ip: string | null;
  synthetic: boolean;
  captured_at: string;
}

export interface FridaScript {
  id: string;
  target_app_id: string | null;
  name: string;
  platform: string;
  category: string;
  target_framework: string;
  conditions: string[];
  risk: string;
  content: string;
  source: string;
  approval_status: string;
  syntax_status: string;
  success_count: number;
  failure_count: number;
  approved_by: string | null;
  approved_at: string | null;
  approved_sha256: string | null;
  created_at: string;
}

export interface AnalysisToolRun {
  id: string;
  tool_name: string;
  tool_version: string | null;
  status: string;
  command: string[];
  raw_output_path: string | null;
  raw_sha256: string | null;
  error: string | null;
  metadata: Record<string, unknown>;
  synthetic: boolean;
  started_at: string;
  finished_at: string | null;
}

export interface RawFinding {
  id: string;
  source_tool: string;
  rule_id: string;
  fingerprint: string;
  title: string;
  category: string;
  severity: string;
  location: string;
  confidence: number;
  references: Record<string, unknown>;
  synthetic: boolean;
}

export interface ControlTest {
  id: string;
  project_id: string;
  app_id: string;
  run_id: string | null;
  mastg_id: string;
  masvs_id: string;
  platform: string;
  title: string;
  automation: string;
  status: string;
  result: string;
  summary: string;
  replacement_ids: string[];
  source_url: string;
  evidence_ids: string[];
  synthetic: boolean;
  updated_at: string;
  standard: string;
  control_id: string;
  group: string;
  criteria: string[];
  evidence_requirements: string[][];
  finding_categories: string[];
  finding_ids: string[];
  risk: string;
  execution?: {
    lane: "ready_now" | "device_required" | "server_scope_required" | "manual_review";
    capability: string;
    available_now: string[];
    device_required: boolean;
    server_scope_required: boolean;
    test_account_required: boolean;
    state_changing: boolean;
    automatic_execution: boolean;
    next_action: string;
    remediation: string;
  };
}

export interface AIStaticTriage {
  status: string;
  provider: string;
  model: string;
  message: string;
  generated_at: string;
  artifact_sha256: string;
  assessment_profile: string;
  decision_policy: string;
  findings: Array<{
    title: string;
    category: string;
    severity: string;
    verdict: string;
    confidence: number;
    rationale: string;
    additional_checks: string[];
    control_ids: string[];
  }>;
}

export interface AIEvidencePriorityRecommendation {
  control_test_id: string;
  control_id: string;
  title: string;
  risk: string;
  current_result: string;
  priority_score: number;
  priority_band: "urgent" | "high" | "medium" | "low";
  ai_confidence: number;
  ai_mapped: boolean;
  selection_source: "ai_with_local_policy" | "local_policy";
  suggested_evidence_ids: string[];
  suggested_evidence_types: string[];
  missing_requirements: string[][];
  requirements_satisfied: boolean;
  rationale: string;
  decision_boundary: string;
}

export interface AIEvidencePriority {
  version: number;
  run_id: string;
  assessment_profile: string;
  generated_at: string;
  generated_by: "ai_with_local_policy" | "local_policy_fallback";
  provider: string;
  model: string;
  status: string;
  message: string;
  decision_policy: string;
  synthetic: boolean;
  terminal_controls_excluded: number;
  unresolved_controls: number;
  ai_mapped_controls: number;
  ready_with_required_evidence: number;
  recommendations: AIEvidencePriorityRecommendation[];
}

export type AssessmentPlanLane =
  | "ready_now"
  | "device_required"
  | "server_scope_required"
  | "manual_review";

export interface AssessmentPlanControl {
  control_id: string;
  group: string;
  title: string;
  risk: string;
  lane: AssessmentPlanLane;
  queue_status: string;
  screening_completed: boolean;
  candidate_count: number;
  ai_mapped: boolean;
  static_candidates: Array<{
    source: string;
    category: string;
    title: string;
    severity: string;
    location: string;
  }>;
  blockers: string[];
  available_now: string[];
  next_action: string;
  test_account_required: boolean;
  state_changing: boolean;
}

export interface AssessmentPlan {
  version: number;
  app_id: string;
  artifact_sha256: string;
  assessment_profile: string;
  generated_at: string;
  generated_by: string;
  decision_policy: string;
  total: number;
  lane_counts: Record<AssessmentPlanLane, number>;
  queue_counts: Record<string, number>;
  ready_now_total: number;
  ready_now_screened: number;
  candidate_controls: number;
  controls: AssessmentPlanControl[];
}

export interface AnalysisOverview {
  app_id: string;
  analysis_status: string;
  catalog_source: Record<string, unknown>;
  tool_runs: AnalysisToolRun[];
  raw_findings: RawFinding[];
  controls: ControlTest[];
  assessment_profile: string;
  assessment_source: Record<string, unknown>;
  assessment_controls: ControlTest[];
}

export interface CoverageData {
  source: Record<string, unknown>;
  standard: string;
  total_catalog: number;
  counts: Record<string, number>;
  result_counts: Record<string, number>;
  tests: ControlTest[];
}

export interface FindingSource {
  id: string;
  source_tool: string;
  source_rule_id: string;
  fingerprint: string;
  raw_finding_id: string | null;
  evidence_ids: string[];
  created_at: string;
}

export interface DashboardData {
  counts: {
    projects: number;
    runs: number;
    findings: number;
    evidence: number;
  };
  recent_runs: DiagnosticRun[];
  recent_findings: Finding[];
}

export interface LiveEvent {
  type: string;
  channel: string;
  timestamp?: string;
  data: Record<string, unknown>;
}

export interface FridaHealth {
  active: boolean;
  healthy: boolean;
  run_id: string;
  mode?: string;
  app_target?: string;
  transport?: string;
  device_id?: string | null;
  endpoint?: string | null;
  actual_device?: {
    id?: string | null;
    name?: string | null;
    type?: string | null;
  };
  buffer_count?: number;
  buffer_capacity?: number;
  total_message_count?: number;
  dropped_count?: number;
  truncated_count?: number;
  stream_sampled_count?: number;
  transcript_bytes?: number;
  transcript_max_bytes?: number;
  cleanup_status?: string;
  synthetic?: boolean;
}

export interface NavigationStateSummary {
  fingerprint: string;
  package: string;
  activity: string;
  window: string;
  visible_text: string[];
  text_hash: string;
  captured_at: string;
  element_count: number;
}

export interface NavigationActionSummary {
  sequence: number;
  action_type: string;
  element_id: string | null;
  label: string;
  risk: string;
  source_state: string;
  destination_state: string | null;
  result: CapabilityStatus;
  message: string;
  timestamp: string;
  evidence_ids: string[];
  synthetic: boolean;
}

export interface PendingNavigationAction {
  id: string;
  action_type: string;
  element_id: string;
  label: string;
  risk: string;
  rationale: string;
  requires_approval: boolean;
  state_fingerprint: string;
  package: string;
  activity: string;
  status: string;
  queued_at: string;
  approval_eligible?: boolean;
  result_evidence_id?: string;
  executed_at?: string;
}

export interface NavigationAIRankingRecommendation {
  candidate_id: string;
  label: string;
  priority_score: number;
  confidence: number;
  rationale: string;
}

export interface NavigationAIRanking {
  state_fingerprint: string;
  activity: string;
  provider: string;
  model: string;
  status: CapabilityStatus;
  message: string;
  recommendations: NavigationAIRankingRecommendation[];
  effective_order: string[];
  local_candidate_count: number;
  ignored_ai_candidate_count: number;
  decision_policy: "advisory_order_local_safety_authoritative";
  generated_at: string;
  synthetic: boolean;
}

export interface NavigationSummary {
  status: CapabilityStatus;
  message: string;
  termination_reason: string;
  states: NavigationStateSummary[];
  actions: NavigationActionSummary[];
  pending_approval: PendingNavigationAction[];
  approved_actions?: PendingNavigationAction[];
  ai_rankings?: NavigationAIRanking[];
  ai_ranking_policy?: string;
  state_count: number;
  action_count: number;
  graph_evidence_id?: string;
  synthetic: boolean;
}

export interface StorageFileChange {
  path: string;
  category: string;
  change_type: "created" | "modified" | "deleted";
  before_size: number | null;
  after_size: number | null;
  before_sha256: string | null;
  after_sha256: string | null;
  size_changed: boolean;
  hash_changed: boolean;
}

export interface StorageDatabaseArtifact {
  path: string;
  size: number;
  sha256: string;
  tables: Array<{
    name: string;
    columns: Array<{ name: string; type: string }>;
    row_count: number;
    preview: Array<Record<string, unknown>>;
    masked: boolean;
  }>;
  masked: boolean;
  status: CapabilityStatus;
  message: string;
}

export interface StorageSummary {
  status: CapabilityStatus;
  message: string;
  before_file_count: number;
  after_file_count: number;
  change_count: number;
  changes: StorageFileChange[];
  databases: StorageDatabaseArtifact[];
  clipboard: Record<string, unknown>;
  evidence_ids: string[];
  synthetic: boolean;
}

export interface NetworkTestCandidateSummary {
  id: string;
  test_type: string;
  source_flow_id: string;
  method: string;
  endpoint: string;
  modified_fields: Array<Record<string, unknown>>;
  expected_result: string;
  risk: string;
  requires_approval: boolean;
  auto_executable: boolean;
  rationale: string;
  status: string;
  synthetic: boolean;
  last_result?: {
    status: string;
    evidence_id: string;
    executed_at: string;
  };
}

export interface NetworkTestingSummary {
  status: CapabilityStatus;
  message: string;
  flow_count: number;
  candidate_count: number;
  executed_count: number;
  pending_count: number;
  analyses: Array<{
    source_flow_id: string;
    method: string;
    origin: string;
    endpoint: string;
    content_type: string;
    auth_scheme: string | null;
    cookie_names: string[];
    object_id_candidates: Array<Record<string, unknown>>;
    protocol_style: string;
    sensitive_response_fields: string[];
  }>;
  candidates: NetworkTestCandidateSummary[];
  executions: Array<{
    candidate_id: string;
    status: CapabilityStatus;
    message: string;
    comparison: Record<string, unknown> | null;
    evidence_ids: string[];
    synthetic: boolean;
  }>;
  pending_approval: NetworkTestCandidateSummary[];
  synthetic: boolean;
  truncated: boolean;
}
