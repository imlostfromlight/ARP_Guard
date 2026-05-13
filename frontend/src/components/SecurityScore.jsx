import React from 'react'

export default function SecurityScore({ score }) {
  const r = 54
  const circ = 2 * Math.PI * r
  const pct = Math.max(0, Math.min(100, score))
  const dash = (pct / 100) * circ
  const color = pct > 60 ? '#48bb78' : pct > 30 ? '#ed8936' : '#e53e3e'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={130} height={130} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={65} cy={65} r={r} fill="none" stroke="#1e2130" strokeWidth={10} />
        <circle
          cx={65} cy={65} r={r} fill="none"
          stroke={color} strokeWidth={10}
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray .6s ease, stroke .6s ease' }}
        />
        <text x={65} y={65} textAnchor="middle" dominantBaseline="central"
          style={{ fill: color, fontSize: 26, fontWeight: 700, fontFamily: 'monospace', transform: 'rotate(90deg)', transformOrigin: '65px 65px' }}>
          {Math.round(pct)}
        </text>
        <text x={65} y={82} textAnchor="middle"
          style={{ fill: '#718096', fontSize: 10, fontFamily: 'sans-serif', transform: 'rotate(90deg)', transformOrigin: '65px 65px' }}>
          SCORE
        </text>
      </svg>
    </div>
  )
}
