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
}

export interface AnalysisOverview {
  app_id: string;
  analysis_status: string;
  catalog_source: Record<string, unknown>;
  tool_runs: AnalysisToolRun[];
  raw_findings: RawFinding[];
  controls: ControlTest[];
}

export interface CoverageData {
  source: Record<string, unknown>;
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

export interface NavigationSummary {
  status: CapabilityStatus;
  message: string;
  termination_reason: string;
  states: NavigationStateSummary[];
  actions: NavigationActionSummary[];
  pending_approval: PendingNavigationAction[];
  approved_actions?: PendingNavigationAction[];
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
