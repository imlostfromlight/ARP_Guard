import React from 'react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'

const fmt = (v) => v > 1024 * 1024
  ? `${(v / 1024 / 1024).toFixed(1)} MB/s`
  : v > 1024
    ? `${(v / 1024).toFixed(1)} KB/s`
    : `${Math.round(v)} B/s`

export default function BitrateChart({ data }) {
  return (
    <div style={{ background: '#161922', borderRadius: 10, padding: '14px 18px' }}>
      <div style={{ fontSize: 12, color: '#718096', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 }}>
        Live Traffic — Promiscuous Mode
      </div>
      <ResponsiveContainer width="100%" height={160}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#4f6ef7" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#4f6ef7" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2130" />
          <XAxis dataKey="t" hide />
          <YAxis tickFormatter={fmt} width={70} tick={{ fill: '#718096', fontSize: 11 }} />
          <Tooltip
            contentStyle={{ background: '#1e2130', border: '1px solid #2d3348', borderRadius: 6 }}
            labelStyle={{ display: 'none' }}
            formatter={(v) => [fmt(v), 'Bitrate']}
          />
          <Area type="monotone" dataKey="bps" stroke="#4f6ef7" fill="url(#bg)" strokeWidth={2} dot={false} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
