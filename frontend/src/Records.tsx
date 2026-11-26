import React, { useState } from 'react'
import { RedactionBar } from './components/RedactionBar'
import type { RecordSummary } from './types'

interface RecordsProps {
  organization: string
  userClearance: string
  records: RecordSummary[]
}

const ACCESS_ORDER: Record<string, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
}

const LEVELS = ['ALL', 'PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED']

export const Records: React.FC<RecordsProps> = ({
  organization,
  userClearance,
  records,
}) => {
  const [search, setSearch] = useState('')
  const [levelFilter, setLevelFilter] = useState('ALL')

  const sorted = [...records].sort((a, b) => (ACCESS_ORDER[a.access_level] ?? 9) - (ACCESS_ORDER[b.access_level] ?? 9))
  const filtered = sorted.filter((rec) => {
    const matchesLevel = levelFilter === 'ALL' || rec.access_level.toUpperCase() === levelFilter
    const q = search.trim().toLowerCase()
    const matchesSearch =
      !q ||
      rec.doc_id.toLowerCase().includes(q) ||
      rec.title.toLowerCase().includes(q) ||
      rec.category.toLowerCase().includes(q)
    return matchesLevel && matchesSearch
  })

  const [selectedId, setSelectedId] = useState<string>(sorted[0]?.doc_id || '')
  const selected = sorted.find((r) => r.doc_id === selectedId) || filtered[0] || sorted[0]

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Company Records</h1>
          <p className="page-subtitle">
            {organization} — Server-enforced permissions by clearance level ({userClearance.toUpperCase()}). Restricted contents are never transmitted to unauthorized clients.
          </p>
        </div>
        <div className="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>
          {records.filter((r) => r.accessible).length} AUTHORIZED / {records.filter((r) => !r.accessible).length} REDACTED
        </div>
      </div>

      <div className="filter-toolbar">
        <input
          className="search-input"
          placeholder="Search records by ID, title, or category..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div className="filter-group">
          {LEVELS.map((lvl) => (
            <button
              key={lvl}
              type="button"
              className={`btn btn-sm ${levelFilter === lvl ? 'btn-primary' : ''}`}
              onClick={() => setLevelFilter(lvl)}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      <div className="records-layout">
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Record ID</th>
                <th>Document &amp; Category</th>
                <th>Access</th>
                <th>Server Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((rec) => (
                <tr
                  key={rec.doc_id}
                  className={`clickable ${selected?.doc_id === rec.doc_id ? 'selected-row' : ''}`}
                  onClick={() => setSelectedId(rec.doc_id)}
                >
                  <td className="mono" style={{ fontSize: 11, fontWeight: 600, whiteSpace: 'nowrap' }}>
                    {rec.doc_id}
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--ink)' }}>{rec.title}</div>
                    <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                      {rec.category} · {rec.owner}
                    </div>
                  </td>
                  <td>
                    <span className={`record-badge ${rec.access_level}`}>{rec.access_level}</span>
                  </td>
                  <td style={{ minWidth: 145 }}>
                    {rec.redacted ? (
                      <RedactionBar label={rec.denial_rule || 'R01'} />
                    ) : (
                      <span className="rule-tag allow">AUTHORIZED</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          {selected ? (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <span className="mono" style={{ fontSize: 12, fontWeight: 600 }}>
                  {selected.doc_id} · {selected.category.toUpperCase()}
                </span>
                <span className={`record-badge ${selected.access_level}`}>{selected.access_level}</span>
              </div>

              <h2 className="serif" style={{ fontSize: 24, marginBottom: 8 }}>
                {selected.title}
              </h2>
              <div className="mono" style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 16 }}>
                OWNER: {selected.owner} | UPDATED: {selected.last_updated}
              </div>

              {selected.accessible && selected.content ? (
                <div>
                  <div className="card-muted" style={{ marginBottom: 16, fontSize: 13 }}>
                    <strong>Summary:</strong> {selected.summary}
                  </div>
                  <pre
                    style={{
                      whiteSpace: 'pre-wrap',
                      fontFamily: 'var(--font-sans)',
                      fontSize: 13,
                      lineHeight: 1.65,
                      color: 'var(--charcoal)',
                      margin: 0,
                      borderTop: '1px solid var(--border)',
                      paddingTop: 16,
                    }}
                  >
                    {selected.content}
                  </pre>
                </div>
              ) : (
                <div>
                  <div className="redaction-block" style={{ marginBottom: 16 }}>
                    <span>Access Denied — Document Content Withheld Server-Side</span>
                    <span>Rule {selected.denial_rule || 'R01'}</span>
                  </div>
                  <p style={{ color: 'var(--charcoal)', marginBottom: 14 }}>
                    {selected.denial_reason || 'Your authenticated role does not hold sufficient clearance for this record.'}
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }} aria-label="Redacted content placeholder">
                    <RedactionBar width="92%" />
                    <RedactionBar width="78%" />
                    <RedactionBar width="85%" />
                    <RedactionBar width="64%" />
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p style={{ color: 'var(--muted)' }}>Select a record to inspect.</p>
          )}
        </div>
      </div>
    </div>
  )
}
