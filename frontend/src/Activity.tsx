import React, { useState } from 'react'
import type { ActivityEvent } from './types'

interface ActivityProps {
  events: ActivityEvent[]
  total: number
  onRefresh: (decision?: string) => void
}

const DECISIONS = ['ALL', 'ALLOW', 'DENY', 'BLOCKED', 'ERROR']

export const Activity: React.FC<ActivityProps> = ({ events, total, onRefresh }) => {
  const [filter, setFilter] = useState('ALL')
  const [search, setSearch] = useState('')

  const handleFilter = (next: string) => {
    setFilter(next)
    onRefresh(next)
  }

  const visibleEvents = events.filter((ev) => {
    const q = search.trim().toLowerCase()
    if (!q) return true
    return (
      ev.request_id.toLowerCase().includes(q) ||
      ev.operation.toLowerCase().includes(q) ||
      ev.triggered_rule.toLowerCase().includes(q) ||
      ev.reason.toLowerCase().includes(q) ||
      ev.user_id.toLowerCase().includes(q)
    )
  })

  const allowCount = events.filter((e) => e.access_decision === 'ALLOW').length
  const denyCount = events.filter((e) => e.access_decision === 'DENY' || e.access_decision === 'BLOCKED').length
  const errCount = events.filter((e) => e.access_decision === 'ERROR').length

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Activity</h1>
          <p className="page-subtitle">
            Real backend security events recorded under Rule R10 without logging confidential document contents.
          </p>
        </div>
        <button type="button" className="btn btn-sm" onClick={() => onRefresh(filter)}>
          Refresh Audit Stream ({total})
        </button>
      </div>

      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-label">Recorded Events</div>
          <div className="kpi-value">{total}</div>
          <div className="kpi-note">SQLite + CloudWatch R10</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Authorized</div>
          <div className="kpi-value">{allowCount}</div>
          <div className="kpi-note">Verified server clearance</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Denied / Blocked</div>
          <div className="kpi-value">{denyCount}</div>
          <div className="kpi-note">Enforced pre-retrieval</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">AWS Errors</div>
          <div className="kpi-value">{errCount}</div>
          <div className="kpi-note">Connectivity / fail-closed</div>
        </div>
      </div>

      <div className="filter-toolbar">
        <input
          className="search-input"
          placeholder="Filter by request ID, rule, operation, or principal..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div className="filter-group">
          {DECISIONS.map((d) => (
            <button
              key={d}
              type="button"
              className={`btn btn-sm ${filter === d ? 'btn-primary' : ''}`}
              onClick={() => handleFilter(d)}
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Request ID</th>
              <th>Principal</th>
              <th>Operation</th>
              <th>Access Decision</th>
              <th>Triggered Rule</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {visibleEvents.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ color: 'var(--muted)', textAlign: 'center', padding: 24 }}>
                  No recorded security events match this filter yet.
                </td>
              </tr>
            ) : (
              visibleEvents.map((ev) => (
                <tr key={ev.id}>
                  <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                    {ev.timestamp.replace('T', ' ').slice(0, 19)}
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {ev.request_id}
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {ev.user_id} ({ev.user_role})
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {ev.operation}
                    {ev.doc_id ? ` [${ev.doc_id}]` : ''}
                    {ev.tool_name ? ` (${ev.tool_name})` : ''}
                  </td>
                  <td>
                    <span
                      className={`rule-tag ${
                        ev.access_decision === 'ALLOW'
                          ? 'allow'
                          : ev.access_decision === 'ERROR'
                            ? 'inconclusive'
                            : 'deny'
                      }`}
                    >
                      {ev.access_decision}
                    </span>
                  </td>
                  <td className="mono" style={{ fontSize: 11, fontWeight: 600 }}>
                    {ev.triggered_rule}
                  </td>
                  <td style={{ fontSize: 12, color: 'var(--charcoal)' }}>{ev.reason}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
