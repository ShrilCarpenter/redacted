import React from 'react'
import type { TabKey, UserProfile } from '../types'

interface SidebarProps {
  activeTab: TabKey
  onSelectTab: (tab: TabKey) => void
  user: UserProfile | null
  recordsCount: { authorized: number; redacted: number }
  eventsTotal: number
  onOpenAuth: () => void
  onSignOut: () => void
}

const NAV_ITEMS: Array<{ key: TabKey; label: string }> = [
  { key: 'workspace', label: 'Workspace' },
  { key: 'records', label: 'Records' },
  { key: 'tests', label: 'Boundary Tests' },
  { key: 'activity', label: 'Activity' },
]

function initials(name: string): string {
  return name
    .split(/\s+/)
    .map((p) => p[0] || '')
    .join('')
    .slice(0, 2)
    .toUpperCase()
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  user,
  recordsCount,
  eventsTotal,
  onOpenAuth,
  onSignOut,
}) => {
  const badgeFor = (key: TabKey): string | null => {
    if (key === 'records') return `${recordsCount.authorized}/${recordsCount.authorized + recordsCount.redacted}`
    if (key === 'tests') return '13'
    if (key === 'activity') return String(eventsTotal)
    return null
  }

  return (
    <aside className="sidebar" aria-label="Workspace Sidebar">
      <div>
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <div className="brand-title">Redacted</div>
            <div className="brand-tagline">Not everything needs to be known.</div>
          </div>
        </div>

        <div className="sidebar-section-label">Enterprise Console</div>
        <nav className="sidebar-nav" aria-label="Primary Workspace Navigation">
          {NAV_ITEMS.map((item) => {
            const count = badgeFor(item.key)
            return (
              <button
                key={item.key}
                type="button"
                className={`sidebar-nav-btn ${activeTab === item.key ? 'active' : ''}`}
                onClick={() => onSelectTab(item.key)}
              >
                <span>{item.label}</span>
                {count !== null && <span className="sidebar-nav-count">{count}</span>}
              </button>
            )
          })}
        </nav>

        <div className="sidebar-policy-box">
          <div className="mono" style={{ fontWeight: 600, color: 'var(--ink)', marginBottom: 4 }}>
            BOUNDARY INVARIANTS
          </div>
          <div>Authorization enforced before S3 retrieval. Rules R01–R10 active across AgentCore Managed Harness.</div>
        </div>
      </div>

      <div className="sidebar-footer">
        {user ? (
          <div className="user-card">
            <div className="user-card-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                <span className="user-monogram">{initials(user.display_name)}</span>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 12 }}>{user.display_name}</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)' }}>
                    {user.title} · {user.department}
                  </div>
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 10 }}>
              <span className="user-pill-clearance">{user.clearance}</span>
              <div style={{ display: 'flex', gap: 6 }}>
                <button type="button" className="btn btn-sm" onClick={onOpenAuth}>
                  Switch
                </button>
                <button type="button" className="btn btn-sm" onClick={onSignOut}>
                  Sign Out
                </button>
              </div>
            </div>
          </div>
        ) : (
          <button type="button" className="btn btn-primary" style={{ width: '100%' }} onClick={onOpenAuth}>
            Sign In to Workspace
          </button>
        )}
      </div>
    </aside>
  )
}
