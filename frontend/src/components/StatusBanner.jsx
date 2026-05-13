import React from 'react'

const s = {
  banner: (alarm) => ({
    padding: '10px 20px',
    borderRadius: 8,
    fontWeight: 700,
    fontSize: 15,
    letterSpacing: '.5px',
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    background: alarm ? '#3b0a0a' : '#0a2b1a',
    border: `2px solid ${alarm ? '#e53e3e' : '#38a169'}`,
    color: alarm ? '#fc8181' : '#68d391',
    transition: 'all .3s',
  }),
  dot: (alarm) => ({
    width: 12, height: 12, borderRadius: '50%',
    background: alarm ? '#e53e3e' : '#38a169',
    boxShadow: `0 0 8px ${alarm ? '#e53e3e' : '#38a169'}`,
    animation: alarm ? 'pulse 1s infinite' : 'none',
  }),
}

export default function StatusBanner({ alerts }) {
  const alarm = alerts.length > 0
  return (
    <>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}`}</style>
      <div style={s.banner(alarm)}>
        <div style={s.dot(alarm)} />
        {alarm
          ? `ARP SPOOFING DETECTED — ${alerts.length} conflict(s)`
          : 'NETWORK SAFE'}
      </div>
    </>
  )
}
