export type TabKey = 'workspace' | 'records' | 'tests' | 'activity'

export interface UserProfile {
  user_id: string
  username: string
  display_name: string
  title: string
  role: string
  department: string
  clearance: 'public' | 'internal' | 'confidential' | 'restricted'
}

export interface DemoAccountInfo {
  username: string
  display_name: string
  title: string
  role: string
  department: string
  clearance: string
}

export interface LoginResponse {
  access_token: string
  token_type: string
  expires_at: string
  user: UserProfile
}

export interface CitationRef {
  doc_id: string
  title: string
  access_level: string
  source: string
}

export interface SecurityDecisionDetail {
  decision: 'ALLOW' | 'DENY' | 'BLOCKED' | 'ERROR'
  triggered_rules: string[]
  reason: string
  request_id: string
  guardrail_intervened: boolean
  hook_events: Array<Record<string, unknown>>
  tool_calls_attempted: Array<Record<string, unknown>>
  unauthorized_tool_calls: Array<Record<string, unknown>>
  stop_reason?: string | null
}

export interface ChatResponse {
  request_id: string
  session_id: string
  answer?: string | null
  refused: boolean
  citations: CitationRef[]
  authorized_documents: string[]
  security: SecurityDecisionDetail
  aws_metadata: Record<string, unknown>
  error?: string | null
}

export interface ConversationTurn {
  id: string
  role: 'user' | 'assistant'
  text: string
  timestamp: string
  response?: ChatResponse
}

export interface RecordSummary {
  doc_id: string
  title: string
  category: string
  access_level: 'public' | 'internal' | 'confidential' | 'restricted'
  owner: string
  last_updated: string
  accessible: boolean
  redacted: boolean
  summary: string
  content?: string | null
  denial_rule?: string | null
  denial_reason?: string | null
}

export interface RecordsListResponse {
  organization: string
  user_clearance: string
  records: RecordSummary[]
}

export interface BoundaryTestCase {
  test_id: string
  title: string
  category: 'adversarial' | 'legitimate'
  prompts: string[]
  expected_behavior: string
  expected_rules: string[]
  target_doc_ids: string[]
}

export interface BoundaryTestResult {
  test_id: string
  title: string
  category: 'adversarial' | 'legitimate'
  prompts: string[]
  actual_response?: string | null
  expected_behavior: string
  expected_rules: string[]
  triggered_rules: string[]
  status: 'pass' | 'fail' | 'inconclusive'
  evaluation_reason: string
  tool_calls_attempted: Array<Record<string, unknown>>
  unauthorized_tool_calls: Array<Record<string, unknown>>
  unauthorized_data_accessed: boolean
  guardrail_intervened: boolean
  hook_events: Array<Record<string, unknown>>
  request_ids: string[]
  executed_at: string
  error?: string | null
}

export interface RunTestsResponse {
  aws_connected: boolean
  harness_arn: string
  executed_at: string
  summary: {
    total: number
    pass: number
    fail: number
    inconclusive: number
  }
  results: BoundaryTestResult[]
}

export interface ActivityEvent {
  id: number
  timestamp: string
  request_id: string
  user_id: string
  user_role: string
  operation: string
  access_decision: 'ALLOW' | 'DENY' | 'BLOCKED' | 'ERROR'
  triggered_rule: string
  reason: string
  doc_id?: string | null
  tool_name?: string | null
  aws_trace_id?: string | null
}

export interface ActivityResponse {
  events: ActivityEvent[]
  total: number
}

export interface AwsStatusResponse {
  aws_connected: boolean
  region: string
  account_id?: string | null
  caller_arn?: string | null
  harness_configured: boolean
  harness_arn: string
  harness_status?: string | null
  guardrail_configured: boolean
  guardrail_id: string
  s3_bucket_configured: boolean
  s3_documents_bucket: string
  cloudwatch_log_group: string
  allowed_tools: string[]
  error?: string | null
}
