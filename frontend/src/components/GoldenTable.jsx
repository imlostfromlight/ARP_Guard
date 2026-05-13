import React, { useState } from 'react'

const API = '/api'

export default function GoldenTable({ table, onRefresh }) {
  const [ip, setIp] = useState('')
  const [mac, setMac] = useState('')

  const add = async () => {
    if (!ip || !mac) return
    await fetch(`${API}/golden-table`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, mac }),
    })
    setIp(''); setMac('')
    onRefresh()
  }

  const remove = async (ip) => {
    await fetch(`${API}/golden-table/${ip}`, { method: 'DELETE' })
    onRefresh()
  }

  return (
    <div style={{ background: '#161922', borderRadius: 10, padding: '14px 18px' }}>
      <div style={{ fontSize: 12, color: '#718096', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
        Golden Table (Trusted Devices)
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <input value={ip} onChange={e => setIp(e.target.value)} placeholder="IP  e.g. 192.168.1.1" style={{ flex: 1 }} />
        <input value={mac} onChange={e => setMac(e.target.value)} placeholder="MAC  e.g. aa:bb:cc:dd:ee:ff" style={{ flex: 1 }} />
        <button onClick={add} style={{ background: '#4f6ef7', color: '#fff' }}>Add</button>
      </div>

      {Object.keys(table).length === 0 ? (
        <div style={{ color: '#4a5568', fontSize: 13 }}>No entries — add your router's IP/MAC above.</div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ color: '#718096' }}>
              <th style={th}>IP Address</th>
              <th style={th}>Trusted MAC</th>
              <th style={th}></th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(table).map(([ip, mac]) => (
              <tr key={ip} style={{ borderTop: '1px solid #1e2130' }}>
                <td style={td}>{ip}</td>
                <td style={{ ...td, fontFamily: 'monospace', color: '#68d391' }}>{mac}</td>
                <td style={td}>
                  <button onClick={() => remove(ip)} style={{ background: '#742a2a', color: '#fc8181', padding: '3px 10px' }}>✕</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

const th = { textAlign: 'left', padding: '4px 8px', fontWeight: 600 }
const td = { padding: '6px 8px' }
