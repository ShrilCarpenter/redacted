import React from 'react'
import type { AwsStatusResponse, TabKey } from '../types'

interface TopBarProps {
  activeTab: TabKey
  awsStatus: AwsStatusResponse | null
}

const TAB_TITLES: Record<TabKey, string> = {
  workspace: 'Workspace / Assistant Session',
  records: 'Records / Access-Controlled Registry',
  tests: 'Boundary Tests / Adversarial Harness Verification',
  activity: 'Activity / Security Audit Trail',
}

export const TopBar: React.FC<TopBarProps> = ({ activeTab, awsStatus }) => {
  const isReady = Boolean(awsStatus?.aws_connected && awsStatus?.harness_configured && awsStatus?.harness_status === 'READY')
  const statusLabel = awsStatus
    ? isReady
      ? `AGENTCORE READY (${awsStatus.region})`
      : awsStatus.aws_connected
        ? 'HARNESS NOT DEPLOYED'
        : 'AWS DISCONNECTED'
    : 'AWAITING SESSION'

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <div className="topbar-breadcrumb">
          <span className="mono" style={{ fontSize: 11 }}>NORTHBRIDGE HOLDINGS GROUP</span>
          <span>/</span>
          <strong>{TAB_TITLES[activeTab]}</strong>
        </div>

        <div className="topbar-meta">
          <div
            className={`status-chip ${isReady ? 'connected' : 'disconnected'}`}
            title={awsStatus?.error || awsStatus?.harness_arn || 'AWS AgentCore Managed Harness status'}
          >
            <span>{statusLabel}</span>
          </div>
          {awsStatus?.guardrail_configured && (
            <span className="status-chip">GUARDRAIL: {awsStatus.guardrail_id}</span>
          )}
        </div>
      </div>
    </header>
  )
}
