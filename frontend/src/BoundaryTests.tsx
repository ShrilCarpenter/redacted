import React, { useEffect, useState } from 'react'
import { api } from './api/client'
import type { AwsStatusResponse, BoundaryTestCase, BoundaryTestResult, RunTestsResponse } from './types'

interface BoundaryTestsProps {
  awsStatus: AwsStatusResponse | null
  onActivityUpdated: () => void
}

export const BoundaryTests: React.FC<BoundaryTestsProps> = ({
  awsStatus,
  onActivityUpdated,
}) => {
  const [cases, setCases] = useState<BoundaryTestCase[]>([])
  const [resultsById, setResultsById] = useState<Record<string, BoundaryTestResult>>({})
  const [lastRunMeta, setLastRunMeta] = useState<Omit<RunTestsResponse, 'results'> | null>(null)
  const [runningId, setRunningId] = useState<string | null>(null)
  const [runningAll, setRunningAll] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'adversarial' | 'legitimate'>('all')
  const [expandedId, setExpandedId] = useState<string | null>('T01')

  useEffect(() => {
    api
      .getTests()
      .then(setCases)
      .catch((err) => setLoadError(err instanceof Error ? err.message : 'Failed to load boundary tests'))
  }, [])

  const runSingle = async (testId: string) => {
    setRunningId(testId)
    setExpandedId(testId)
    try {
      const resp = await api.runTests([testId])
      setLastRunMeta({
        aws_connected: resp.aws_connected,
        harness_arn: resp.harness_arn,
        executed_at: resp.executed_at,
        summary: resp.summary,
      })
      setResultsById((prev) => {
        const next = { ...prev }
        for (const r of resp.results) next[r.test_id] = r
        return next
      })
      onActivityUpdated()
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Test execution failed')
    } finally {
      setRunningId(null)
    }
  }

  const runAll = async () => {
    setRunningAll(true)
    setLoadError(null)
    try {
      const resp = await api.runTests()
      setLastRunMeta({
        aws_connected: resp.aws_connected,
        harness_arn: resp.harness_arn,
        executed_at: resp.executed_at,
        summary: resp.summary,
      })
      const map: Record<string, BoundaryTestResult> = {}
      for (const r of resp.results) map[r.test_id] = r
      setResultsById(map)
      onActivityUpdated()
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Test suite execution failed')
    } finally {
      setRunningAll(false)
    }
  }

  const exportJson = () => {
    const executed = cases.map((c) => resultsById[c.test_id]).filter(Boolean)
    const payload = {
      exported_at: new Date().toISOString(),
      aws_connected: lastRunMeta?.aws_connected ?? false,
      harness_arn: lastRunMeta?.harness_arn ?? awsStatus?.harness_arn ?? '',
      results: executed,
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `redacted-boundary-tests-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const executedList = Object.values(resultsById)
  const counts = {
    total: cases.length,
    pass: executedList.filter((r) => r.status === 'pass').length,
    fail: executedList.filter((r) => r.status === 'fail').length,
    inconclusive: executedList.filter((r) => r.status === 'inconclusive').length,
  }

  const filteredCases = cases.filter((tc) => {
    const matchesCat = categoryFilter === 'all' || tc.category === categoryFilter
    const q = search.trim().toLowerCase()
    const matchesSearch =
      !q ||
      tc.test_id.toLowerCase().includes(q) ||
      tc.title.toLowerCase().includes(q) ||
      tc.prompts.some((p) => p.toLowerCase().includes(q))
    return matchesCat && matchesSearch
  })

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Boundary Tests</h1>
          <p className="page-subtitle">
            Adversarial and legitimate verification executed live against Amazon Bedrock AgentCore Managed Harness. Unavailable AWS returns INCONCLUSIVE — never a fabricated pass.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button type="button" className="btn" onClick={exportJson} disabled={executedList.length === 0}>
            Export JSON ({executedList.length})
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={runAll}
            disabled={runningAll || runningId !== null}
          >
            {runningAll ? 'Running All Tests...' : 'Run All Tests'}
          </button>
        </div>
      </div>

      {awsStatus && (!awsStatus.aws_connected || !awsStatus.harness_configured) && (
        <div className="alert alert-error">
          <strong>AWS Connection Unavailable:</strong>{' '}
          {awsStatus.error || 'Live AgentCore Managed Harness connection is required. Running tests now will accurately report INCONCLUSIVE.'}
        </div>
      )}

      {loadError && <div className="alert alert-error">{loadError}</div>}

      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-label">Total Test Cases</div>
          <div className="kpi-value">{counts.total}</div>
          <div className="kpi-note">10 adversarial + 3 legitimate</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Passed</div>
          <div className="kpi-value">{counts.pass}</div>
          <div className="kpi-note">Zero unauthorized access</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Failed</div>
          <div className="kpi-value">{counts.fail}</div>
          <div className="kpi-note">Policy or leak violation</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Inconclusive</div>
          <div className="kpi-value">{counts.inconclusive}</div>
          <div className="kpi-note">{lastRunMeta ? 'Last run evaluated' : 'Awaiting live run'}</div>
        </div>
      </div>

      <div className="filter-toolbar">
        <input
          className="search-input"
          placeholder="Search test ID, title, or prompt..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div className="filter-group">
          {(['all', 'adversarial', 'legitimate'] as const).map((cat) => (
            <button
              key={cat}
              type="button"
              className={`btn btn-sm ${categoryFilter === cat ? 'btn-primary' : ''}`}
              onClick={() => setCategoryFilter(cat)}
            >
              {cat.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Category</th>
              <th>Test &amp; Prompt</th>
              <th>Expected Rules</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredCases.map((tc) => {
              const res = resultsById[tc.test_id]
              const isBusy = runningAll || runningId === tc.test_id
              const isExpanded = expandedId === tc.test_id
              return (
                <React.Fragment key={tc.test_id}>
                  <tr
                    className={`clickable ${isExpanded ? 'selected-row' : ''}`}
                    onClick={() => setExpandedId(isExpanded ? null : tc.test_id)}
                  >
                    <td className="mono" style={{ fontWeight: 700, fontSize: 12 }}>
                      {tc.test_id}
                    </td>
                    <td>
                      <span className="record-badge">{tc.category}</span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--ink)' }}>{tc.title}</div>
                      <div className="mono" style={{ fontSize: 11, color: 'var(--muted)', marginTop: 3 }}>
                        {tc.prompts[0]}
                        {tc.prompts.length > 1 ? ` (+${tc.prompts.length - 1} turns)` : ''}
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: 11 }}>
                      {tc.expected_rules.length > 0 ? tc.expected_rules.join(', ') : 'ALLOW'}
                    </td>
                    <td>
                      {res ? (
                        <span
                          className={`rule-tag ${
                            res.status === 'pass' ? 'allow' : res.status === 'fail' ? 'fail' : 'inconclusive'
                          }`}
                        >
                          {res.status.toUpperCase()}
                        </span>
                      ) : (
                        <span className="mono" style={{ fontSize: 11, color: 'var(--subtle)' }}>
                          NOT RUN
                        </span>
                      )}
                    </td>
                    <td onClick={(e) => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => void runSingle(tc.test_id)}
                        disabled={runningAll || runningId !== null}
                      >
                        {isBusy ? 'Running...' : 'Run Test'}
                      </button>
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr>
                      <td colSpan={6} style={{ background: 'var(--surface)', padding: 16 }}>
                        <div style={{ marginBottom: 10 }}>
                          <div className="field-label">Prompt Sequence</div>
                          {tc.prompts.map((p, idx) => (
                            <div
                              key={idx}
                              className="mono"
                              style={{
                                background: 'var(--bg)',
                                border: '1px solid var(--border)',
                                padding: '8px 10px',
                                fontSize: 12,
                                marginBottom: 6,
                              }}
                            >
                              {tc.prompts.length > 1 ? `[Turn ${idx + 1}] ` : ''}
                              {p}
                            </div>
                          ))}
                        </div>

                        <div style={{ fontSize: 13, color: 'var(--charcoal)', marginBottom: 10 }}>
                          <strong>Expected behavior:</strong> {tc.expected_behavior}
                        </div>

                        {res ? (
                          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                            <div style={{ marginBottom: 8 }}>
                              <strong>Evaluation:</strong> {res.evaluation_reason}
                            </div>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 10 }} className="mono">
                              <span style={{ fontSize: 11 }}>
                                Triggered rules: {res.triggered_rules.length > 0 ? res.triggered_rules.join(', ') : 'NONE'}
                              </span>
                              <span style={{ fontSize: 11 }}>
                                | Tool calls attempted: {res.tool_calls_attempted.length}
                              </span>
                              <span style={{ fontSize: 11 }}>
                                | Unauthorized tool calls blocked: {res.unauthorized_tool_calls.length}
                              </span>
                              <span style={{ fontSize: 11 }}>
                                | Unauthorized data accessed: {res.unauthorized_data_accessed ? 'YES' : 'NO'}
                              </span>
                            </div>

                            {res.error ? (
                              <div className="alert alert-error" style={{ marginBottom: 0 }}>
                                <strong>AWS Execution Error:</strong> {res.error}
                              </div>
                            ) : (
                              <div>
                                <div className="field-label">Actual Agent Response</div>
                                <div
                                  style={{
                                    background: 'var(--bg)',
                                    border: '1px solid var(--border)',
                                    padding: 10,
                                    whiteSpace: 'pre-wrap',
                                    fontSize: 12,
                                  }}
                                >
                                  {res.actual_response || '[Empty response]'}
                                </div>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                            Click <strong>Run Test</strong> to invoke Amazon Bedrock AgentCore Managed Harness for this case.
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
