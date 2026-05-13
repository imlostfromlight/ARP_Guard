import React from 'react'

const DOT_ANIM = `
@keyframes flow1 { 0%{left:0;opacity:0} 10%{opacity:1} 90%{opacity:1} 100%{left:calc(100% - 10px);opacity:0} }
@keyframes flow2 { 0%{left:0;opacity:0} 10%{opacity:1} 90%{opacity:1} 100%{left:calc(100% - 10px);opacity:0} }
`

function Node({ label, ip, mac, color, borderColor }) {
  return (
    <div style={{
      background: '#0f1117',
      border: `2px solid ${borderColor}`,
      borderRadius: 10,
      padding: '10px 16px',
      minWidth: 160,
      textAlign: 'center',
    }}>
      <div style={{ fontSize: 11, color: borderColor, fontWeight: 700, textTransform: 'uppercase', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 14, color: '#e2e8f0', fontWeight: 600, fontFamily: 'monospace' }}>{ip || '—'}</div>
      {mac && <div style={{ fontSize: 10, color: '#4a5568', fontFamily: 'monospace', marginTop: 2 }}>{mac}</div>}
    </div>
  )
}

function Arrow({ active, color, delay = '0s' }) {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', position: 'relative', minWidth: 60 }}>
      <div style={{ width: '100%', height: 2, background: active ? color : '#2d3748' }} />
      <div style={{ position: 'absolute', right: 0, color: active ? color : '#2d3748', fontSize: 16, lineHeight: 1 }}>▶</div>
      {active && (
        <div style={{
          position: 'absolute',
          width: 10, height: 10,
          borderRadius: '50%',
          background: color,
          boxShadow: `0 0 6px ${color}`,
          animation: `flow1 1.2s ${delay} infinite linear`,
        }} />
      )}
    </div>
  )
}

export default function PacketMap({ attacking, victim, localInfo, gateway }) {
  const active = attacking && !!victim

  return (
    <div style={{ background: '#161922', borderRadius: 10, padding: '14px 18px' }}>
      <style>{DOT_ANIM}</style>
      <div style={{ fontSize: 12, color: '#718096', marginBottom: 14, textTransform: 'uppercase', letterSpacing: 1 }}>
        Packet Flow Map
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
        <Node
          label="Victim"
          ip={victim?.ip || 'No target'}
          mac={victim?.mac}
          color={active ? '#fc8181' : '#4a5568'}
          borderColor={active ? '#e53e3e' : '#2d3748'}
        />
        <Arrow active={active} color="#fc8181" delay="0s" />
        <Node
          label="You (MITM)"
          ip={localInfo?.ip || '—'}
          mac={localInfo?.mac}
          color={active ? '#63b3ed' : '#4a5568'}
          borderColor={active ? '#3182ce' : '#2d3748'}
        />
        <Arrow active={active} color="#63b3ed" delay="0.4s" />
        <Node
          label="Router"
          ip={gateway?.ip || '—'}
          mac={gateway?.mac}
          color={active ? '#68d391' : '#4a5568'}
          borderColor={active ? '#276749' : '#2d3748'}
        />
      </div>
      {!active && (
        <div style={{ marginTop: 10, fontSize: 12, color: '#4a5568', textAlign: 'center' }}>
          Start an attack to see live packet flow
        </div>
      )}
    </div>
  )
}
