import React from 'react'

export default function DeviceList({ devices, gateway, selectedTarget, onSelect, attacking, onAttack, onStopAttack }) {
  if (!devices) return null

  return (
    <div style={{ background: '#161922', borderRadius: 10, padding: '14px 18px' }}>
      <div style={{ fontSize: 12, color: '#718096', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
        Discovered Devices ({devices.length})
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {devices.map(d => {
          const isGw = d.is_gateway
          const isSelected = selectedTarget?.ip === d.ip
          const isAttacked = attacking && isSelected

          return (
            <div key={d.ip} style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '8px 12px',
              borderRadius: 7,
              border: `1px solid ${isAttacked ? '#e53e3e' : isSelected ? '#4f6ef7' : '#1e2130'}`,
              background: isAttacked ? '#2d1515' : isSelected ? '#1a1f3a' : '#0f1117',
              transition: 'all .2s',
            }}>
              {/* Icon */}
              <div style={{ fontSize: 18, minWidth: 24, textAlign: 'center' }}>
                {isGw ? '🌐' : '💻'}
              </div>

              {/* Info */}
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontWeight: 600, color: '#e2e8f0' }}>{d.ip}</span>
                  {isGw && (
                    <span style={{ fontSize: 10, background: '#276749', color: '#68d391', borderRadius: 4, padding: '1px 6px', fontWeight: 700 }}>
                      GATEWAY
                    </span>
                  )}
                  {isAttacked && (
                    <span style={{ fontSize: 10, background: '#742a2a', color: '#fc8181', borderRadius: 4, padding: '1px 6px', fontWeight: 700, animation: 'pulse 1s infinite' }}>
                      UNDER ATTACK
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 12, color: '#4a5568', fontFamily: 'monospace' }}>
                  {d.mac}
                  {d.vendor ? <span style={{ color: '#63b3ed', marginLeft: 10, fontFamily: 'sans-serif' }}>{d.vendor}</span> : null}
                  {d.hostname ? <span style={{ color: '#718096', marginLeft: 10, fontFamily: 'sans-serif' }}>{d.hostname}</span> : null}
                </div>
              </div>

              {/* Actions */}
              {!isGw && (
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    onClick={() => onSelect(d)}
                    style={{
                      background: isSelected ? '#4f6ef7' : '#1e2130',
                      color: isSelected ? '#fff' : '#a0aec0',
                      padding: '4px 12px',
                      fontSize: 12,
                    }}
                  >
                    {isSelected ? '✓ Selected' : 'Select'}
                  </button>
                  {isSelected && (
                    isAttacked
                      ? <button onClick={onStopAttack} style={{ background: '#742a2a', color: '#fc8181', padding: '4px 12px', fontSize: 12 }}>
                          ⏹ Stop
                        </button>
                      : <button
                          onClick={() => onAttack(d, gateway)}
                          disabled={!gateway}
                          style={{ background: '#9b2c2c', color: '#fff', padding: '4px 12px', fontSize: 12 }}
                        >
                          ⚡ Attack
                        </button>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {!gateway && devices.length > 0 && (
        <div style={{ marginTop: 10, fontSize: 12, color: '#dd6b20' }}>
          ⚠ Gateway not found in scan — attack unavailable.
        </div>
      )}
    </div>
  )
}
