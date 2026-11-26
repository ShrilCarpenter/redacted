import React, { useCallback, useEffect, useState } from 'react'
import { Activity } from './Activity'
import { api, getStoredToken, setStoredToken } from './api/client'
import { BoundaryTests } from './BoundaryTests'
import { AuthGateModal } from './components/AuthGateModal'
import { Sidebar } from './components/Sidebar'
import { TopBar } from './components/TopBar'
import { Records } from './Records'
import type { ActivityEvent, AwsStatusResponse, RecordSummary, TabKey, UserProfile } from './types'
import { Workspace } from './Workspace'

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>('workspace')
  const [user, setUser] = useState<UserProfile | null>(null)
  const [authModalOpen, setAuthModalOpen] = useState(false)
  const [awsStatus, setAwsStatus] = useState<AwsStatusResponse | null>(null)
  const [records, setRecords] = useState<RecordSummary[]>([])
  const [organization, setOrganization] = useState('Northbridge Holdings Group')
  const [events, setEvents] = useState<ActivityEvent[]>([])
  const [eventsTotal, setEventsTotal] = useState(0)
  const [booting, setBooting] = useState(true)

  const loadWorkspaceData = useCallback(async (decisionFilter?: string) => {
    try {
      const [statusResp, recResp, actResp] = await Promise.all([
        api.getAwsStatus(),
        api.getRecords(),
        api.getActivity(decisionFilter),
      ])
      setAwsStatus(statusResp)
      setRecords(recResp.records)
      setOrganization(recResp.organization)
      setEvents(actResp.events)
      setEventsTotal(actResp.total)
    } catch {
      // ignore if session expired
    }
  }, [])

  const refreshActivity = useCallback(async (decisionFilter?: string) => {
    try {
      const actResp = await api.getActivity(decisionFilter)
      setEvents(actResp.events)
      setEventsTotal(actResp.total)
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => {
    const token = getStoredToken()
    if (!token) {
      setAuthModalOpen(true)
      setBooting(false)
      return
    }
    api
      .getMe()
      .then((u) => {
        setUser(u)
        return loadWorkspaceData()
      })
      .catch(() => {
        setStoredToken(null)
        setAuthModalOpen(true)
      })
      .finally(() => setBooting(false))
  }, [loadWorkspaceData])

  const handleAuthenticated = (authedUser: UserProfile) => {
    setUser(authedUser)
    void loadWorkspaceData()
  }

  const handleSignOut = () => {
    setStoredToken(null)
    setUser(null)
    setRecords([])
    setEvents([])
    setAwsStatus(null)
    setAuthModalOpen(true)
  }

  const recordsCount = {
    authorized: records.filter((r) => r.accessible).length,
    redacted: records.filter((r) => !r.accessible).length,
  }

  return (
    <div className="app-frame">
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        user={user}
        recordsCount={recordsCount}
        eventsTotal={eventsTotal}
        onOpenAuth={() => setAuthModalOpen(true)}
        onSignOut={handleSignOut}
      />

      <div className="workspace-column">
        <TopBar activeTab={activeTab} awsStatus={awsStatus} />

        <main className="main-container">
          {booting ? (
            <div className="card-muted">Initializing Redacted workspace...</div>
          ) : !user ? (
            <div className="card" style={{ maxWidth: 640, margin: '48px auto' }}>
              <div className="redaction-block" style={{ marginBottom: 16 }}>
                <span>Access Withheld</span>
                <span>Rule R09</span>
              </div>
              <h1 className="serif" style={{ fontSize: 28, marginBottom: 8 }}>
                Authentication Required
              </h1>
              <p style={{ color: 'var(--muted)', marginBottom: 18 }}>
                Authorization could not be established. Authenticate with a server-verified workspace account to inspect authorized records or query the Managed Harness.
              </p>
              <button type="button" className="btn btn-primary" onClick={() => setAuthModalOpen(true)}>
                Sign In to Workspace
              </button>
            </div>
          ) : (
            <>
              {activeTab === 'workspace' && (
                <Workspace
                  user={user}
                  records={records}
                  awsStatus={awsStatus}
                  onActivityUpdated={() => void refreshActivity()}
                />
              )}
              {activeTab === 'records' && (
                <Records
                  organization={organization}
                  userClearance={user.clearance}
                  records={records}
                />
              )}
              {activeTab === 'tests' && (
                <BoundaryTests
                  awsStatus={awsStatus}
                  onActivityUpdated={() => void refreshActivity()}
                />
              )}
              {activeTab === 'activity' && (
                <Activity
                  events={events}
                  total={eventsTotal}
                  onRefresh={(d) => void refreshActivity(d)}
                />
              )}
            </>
          )}
        </main>
      </div>

      <AuthGateModal
        open={authModalOpen}
        canDismiss={Boolean(user)}
        onClose={() => setAuthModalOpen(false)}
        onAuthenticated={handleAuthenticated}
      />
    </div>
  )
}

export default App
