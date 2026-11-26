import React from 'react'

interface RedactionBarProps {
  width?: string
  label?: string
}

export const RedactionBar: React.FC<RedactionBarProps> = ({ width = '100%', label }) => {
  if (label) {
    return (
      <div className="redaction-block" style={{ width }}>
        <span>{label}</span>
        <span>REDACTED</span>
      </div>
    )
  }
  return <span className="redaction-bar" style={{ width }} aria-hidden="true" />
}
