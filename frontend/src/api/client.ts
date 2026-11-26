import type {
  ActivityResponse,
  AwsStatusResponse,
  BoundaryTestCase,
  ChatResponse,
  DemoAccountInfo,
  LoginResponse,
  RecordsListResponse,
  RunTestsResponse,
  UserProfile,
} from '../types'

const TOKEN_KEY = 'redacted_session_token'

export function getStoredToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY)
}

export function setStoredToken(token: string | null): void {
  if (token) {
    sessionStorage.setItem(TOKEN_KEY, token)
  } else {
    sessionStorage.removeItem(TOKEN_KEY)
  }
}

async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getStoredToken()
  const headers = new Headers(init.headers || {})
  headers.set('Content-Type', 'application/json')
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  const res = await fetch(path, { ...init, headers })
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      const body = await res.json()
      if (body?.detail?.message) {
        detail = `[${body.detail.rule || 'DENY'}] ${body.detail.message}`
      } else if (typeof body?.detail === 'string') {
        detail = body.detail
      }
    } catch {
      // ignore non-json error bodies
    }
    throw new Error(detail)
  }
  return (await res.json()) as T
}

export const api = {
  getAccounts: () => apiRequest<DemoAccountInfo[]>('/api/auth/accounts'),
  login: (username: string, password: string) =>
    apiRequest<LoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  getMe: () => apiRequest<UserProfile>('/api/auth/me'),
  getAwsStatus: () => apiRequest<AwsStatusResponse>('/api/aws/status'),
  getRecords: () => apiRequest<RecordsListResponse>('/api/records'),
  getRecordDetail: (docId: string) => apiRequest<Record<string, unknown>>(`/api/records/${encodeURIComponent(docId)}`),
  sendChat: (prompt: string, sessionId?: string) =>
    apiRequest<ChatResponse>('/api/chat', {
      method: 'POST',
      body: JSON.stringify({ prompt, session_id: sessionId }),
    }),
  getTests: () => apiRequest<BoundaryTestCase[]>('/api/tests'),
  runTests: (testIds?: string[]) =>
    apiRequest<RunTestsResponse>('/api/tests/run', {
      method: 'POST',
      body: JSON.stringify({ test_ids: testIds ?? null }),
    }),
  getActivity: (decision?: string) => {
    const q = decision && decision !== 'ALL' ? `?decision=${encodeURIComponent(decision)}` : ''
    return apiRequest<ActivityResponse>(`/api/activity${q}`)
  },
}
