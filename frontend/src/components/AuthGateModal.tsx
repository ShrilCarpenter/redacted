import React, { useEffect, useState } from 'react'
import { api, setStoredToken } from '../api/client'
import type { DemoAccountInfo, UserProfile } from '../types'

interface AuthGateModalProps {
  open: boolean
  canDismiss: boolean
  onClose: () => void
  onAuthenticated: (user: UserProfile) => void
}

const EVAL_PASSWORDS: Record<string, string> = {
  'claire.vance': 'Redacted-Analyst-2026!',
  'marcus.chen': 'Redacted-Ops-2026!',
  'david.okafor': 'Redacted-Legal-2026!',
  'helena.park': 'Redacted-Audit-2026!',
}

export const AuthGateModal: React.FC<AuthGateModalProps> = ({
  open,
  canDismiss,
  onClose,
  onAuthenticated,
}) => {
  const [accounts, setAccounts] = useState<DemoAccountInfo[]>([])
  const [username, setUsername] = useState('claire.vance')
  const [password, setPassword] = useState(EVAL_PASSWORDS['claire.vance'])
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!open) return
    api
      .getAccounts()
      .then(setAccounts)
      .catch(() => setAccounts([]))
  }, [open])

  if (!open) return null

  const selectPersona = (uname: string) => {
    setUsername(uname)
    setPassword(EVAL_PASSWORDS[uname] || '')
    setError(null)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const resp = await api.login(username, password)
      setStoredToken(resp.access_token)
      onAuthenticated(resp.user)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Workspace Authentication">
      <div className="modal-panel">
        <div className="redaction-block" style={{ marginBottom: 18 }}>
          <span>Server-Verified Session Required</span>
          <span>Rule R06 / R09</span>
        </div>

        <h2 className="serif" style={{ fontSize: 24, marginBottom: 6 }}>
          Sign in to Redacted
        </h2>
        <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 0, marginBottom: 16 }}>
          Identity and document clearances are enforced cryptographically on the server. Conversational role claims are never trusted.
        </p>

        {accounts.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div className="field-label">Synthetic Directory Personas</div>
            <div className="persona-grid">
              {accounts.map((acc) => (
                <button
                  key={acc.username}
                  type="button"
                  className={`persona-btn ${username === acc.username ? 'active' : ''}`}
                  onClick={() => selectPersona(acc.username)}
                >
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{acc.display_name}</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)' }}>
                    {acc.title} ({acc.department})
                  </div>
                  <div className="mono" style={{ fontSize: 10, marginTop: 4 }}>
                    CLEARANCE: {acc.clearance.toUpperCase()}
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="field-group">
            <label className="field-label" htmlFor="auth-username">
              Username
            </label>
            <input
              id="auth-username"
              className="field-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </div>

          <div className="field-group">
            <label className="field-label" htmlFor="auth-password">
              Password
            </label>
            <input
              id="auth-password"
              type="password"
              className="field-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>

          {error && <div className="alert alert-error">{error}</div>}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
            {canDismiss && (
              <button type="button" className="btn" onClick={onClose}>
                Cancel
              </button>
            )}
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Authenticating...' : 'Authenticate Session'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
