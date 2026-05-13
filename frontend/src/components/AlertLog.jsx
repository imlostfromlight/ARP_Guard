import React from 'react'

export default function AlertLog({ alerts }) {
  return (
    <div style={{ background: '#161922', borderRadius: 10, padding: '14px 18px' }}>
      <div style={{ fontSize: 12, color: '#718096', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 }}>
        ARP Conflict Log
      </div>
      {alerts.length === 0 ? (
        <div style={{ color: '#4a5568', fontSize: 13 }}>No conflicts detected.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {alerts.slice(-50).reverse().map((a, i) => (
            <div key={i} style={{
              background: '#2d1515',
              border: '1px solid #742a2a',
              borderRadius: 6,
              padding: '8px 12px',
              fontSize: 13,
              fontFamily: 'monospace',
            }}>
              <span style={{ color: '#fc8181', fontWeight: 700 }}>SPOOF </span>
              <span style={{ color: '#fbd38d' }}>{a.ip}</span>
              {' '}claimed by{' '}
              <span style={{ color: '#fc8181' }}>{a.fake_mac}</span>
              {' '}(real: <span style={{ color: '#68d391' }}>{a.real_mac}</span>)
              <span style={{ float: 'right', color: '#4a5568' }}>{a.time}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
