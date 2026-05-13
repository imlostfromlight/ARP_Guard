import React, { useState } from 'react'

const decode = s => { try { return decodeURIComponent(s) } catch { return s } }

const s = {
  wrap:    { background: '#161922', borderRadius: 10, padding: '14px 18px' },
  label:   { fontSize: 12, color: '#718096', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 },
  empty:   { color: '#4a5568', fontSize: 13 },
  list:    { display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 420, overflowY: 'auto' },
  card:    { background: '#2d0a0a', border: '1px solid #9b2c2c', borderRadius: 6, padding: '8px 12px' },
  meta:    { fontSize: 11, color: '#718096', marginBottom: 6 },
  method:  { fontWeight: 700, color: '#fc8181', marginRight: 8 },
  path:    { color: '#feb2b2' },
  status:  { fontWeight: 700, color: '#f6ad55' },
  pre:     { margin: '4px 0 0', fontSize: 11, color: '#fc8181', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'monospace' },
  hdrKey:  { color: '#718096' },
  hdrVal:  { color: '#a0aec0' },
  formWrap:{ marginTop: 6, borderTop: '1px solid #4a1515', paddingTop: 6 },
  credRow: { background: '#5c0000', border: '1px solid #e53e3e', borderRadius: 4, padding: '3px 8px', marginBottom: 3, fontFamily: 'monospace', fontSize: 12 },
  normRow: { padding: '2px 8px', fontFamily: 'monospace', fontSize: 12, color: '#a0aec0' },
  credKey: { color: '#fc8181', fontWeight: 700 },
  credVal: { color: '#fff', fontWeight: 700, fontSize: 13 },
  normKey: { color: '#718096' },
  normVal: { color: '#cbd5e0' },
}

function Headers({ headers }) {
  const [open, setOpen] = useState(false)
  const entries = Object.entries(headers || {})
  if (!entries.length) return null
  return (
    <div style={{ marginTop: 4 }}>
      <span onClick={() => setOpen(o => !o)}
        style={{ fontSize: 11, color: '#4a5568', cursor: 'pointer', userSelect: 'none' }}>
        {open ? '▾' : '▸'} headers ({entries.length})
      </span>
      {open && entries.map(([k, v]) => (
        <div key={k} style={{ fontSize: 11, fontFamily: 'monospace', paddingLeft: 8 }}>
          <span style={s.hdrKey}>{k}: </span><span style={s.hdrVal}>{v}</span>
        </div>
      ))}
    </div>
  )
}

function FormFields({ fields }) {
  if (!fields?.length) return null
  return (
    <div style={s.formWrap}>
      <div style={{ fontSize: 11, color: '#718096', marginBottom: 4 }}>FORM DATA</div>
      {fields.map((f, i) => f.is_cred ? (
        <div key={i} style={s.credRow}>
          🔑 <span style={s.credKey}>{decode(f.key)}</span>
          {' = '}
          <span style={s.credVal}>{decode(f.value)}</span>
        </div>
      ) : (
        <div key={i} style={s.normRow}>
          <span style={s.normKey}>{decode(f.key)}</span>
          {' = '}
          <span style={s.normVal}>{decode(f.value)}</span>
        </div>
      ))}
    </div>
  )
}

export default function HttpCapture({ packets }) {
  return (
    <div style={s.wrap}>
      <div style={s.label}>Live HTTP Intercept (Plain-text leak)</div>
      {packets.length === 0 ? (
        <div style={s.empty}>No plain-text HTTP captured yet.</div>
      ) : (
        <div style={s.list}>
          {packets.slice(-30).reverse().map((p, i) => (
            <div key={i} style={s.card}>
              <div style={s.meta}>{p.src} → {p.dst} &nbsp;|&nbsp; {p.time}</div>

              {p.direction === 'request' ? (
                <>
                  <div>
                    <span style={s.method}>{p.method}</span>
                    <span style={s.path}>{p.path}</span>
                  </div>
                  <Headers headers={p.headers} />
                  {p.form_fields
                    ? <FormFields fields={p.form_fields} />
                    : p.body && <pre style={s.pre}>{p.body}</pre>
                  }
                </>
              ) : (
                <>
                  <span style={s.status}>{p.status}</span>
                  <Headers headers={p.headers} />
                  {p.body && <pre style={s.pre}>{p.body}</pre>}
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
