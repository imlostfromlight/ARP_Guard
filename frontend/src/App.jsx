import React, { useEffect, useRef, useState, useCallback } from 'react'
import StatusBanner from './components/StatusBanner'
import BitrateChart from './components/BitrateChart'
import GoldenTable from './components/GoldenTable'
import AlertLog from './components/AlertLog'
import HttpCapture from './components/HttpCapture'
import DeviceList from './components/DeviceList'
import SecurityScore from './components/SecurityScore'
import PacketMap from './components/PacketMap'

const API = '/api'
const MAX_BITRATE_POINTS = 60
const now = () => new Date().toLocaleTimeString()

export default function App() {
  const [sniffing, setSniffing] = useState(false)
  const [protect, setProtect] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [selectedTarget, setSelectedTarget] = useState(null)
  const [attacking, setAttacking] = useState(false)
  const [dnsActive, setDnsActive] = useState(false)
  const [dnsSpoofed, setDnsSpoofed] = useState([])
  const [phishActive, setPhishActive] = useState(false)
  const [phishPort, setPhishPort] = useState(8888)
  const [phishCaptures, setPhishCaptures] = useState([])
  const [score, setScore] = useState(100)
  const [alerts, setAlerts] = useState([])
  const [alertLog, setAlertLog] = useState([])
  const [httpPackets, setHttpPackets] = useState([])
  const [bitrateData, setBitrateData] = useState([])
  const [goldenTable, setGoldenTable] = useState({})
  const wsRef = useRef(null)

  useEffect(() => {
    fetchGoldenTable()
  }, [])

  const fetchGoldenTable = useCallback(() => {
    fetch(`${API}/golden-table`).then(r => r.json()).then(d => setGoldenTable(d.table)).catch(() => {})
  }, [])

  // ── WebSocket ────────────────────────────────────────────────────────
  const connectWs = useCallback(() => {
    const ws = new WebSocket(`ws://${location.host}/ws`)
    wsRef.current = ws
    ws.onmessage = (e) => {
      if (!e.data) return
      let msg; try { msg = JSON.parse(e.data) } catch { return }
      if (msg.type === 'bitrate') {
        setBitrateData(prev => { const n = [...prev, { t: now(), bps: msg.bps }]; return n.length > MAX_BITRATE_POINTS ? n.slice(-MAX_BITRATE_POINTS) : n })
      }
      if (msg.type === 'arp_alert') {
        const e = { ...msg, time: now() }
        setAlerts(prev => [...prev.filter(a => a.ip !== msg.ip), e])
        setAlertLog(prev => [...prev, e])
        setScore(s => Math.max(0, s - 30))
      }
      if (msg.type === 'arp_clear') { setAlerts(prev => prev.filter(a => a.ip !== msg.ip)); setScore(s => Math.min(100, s + 10)) }
      if (msg.type === 'http_capture') setHttpPackets(prev => [...prev, { ...msg, time: now() }])
      if (msg.type === 'attack_started') { setAttacking(true); setScore(s => Math.max(0, s - 20)) }
      if (msg.type === 'attack_stopped') { setAttacking(false); setScore(s => Math.min(100, s + 20)) }
      if (msg.type === 'dns_spoof') { setDnsSpoofed(prev => [{ ...msg, time: now() }, ...prev].slice(0, 50)); setScore(s => Math.max(0, s - 10)) }
      if (msg.type === 'phish_capture') { setPhishCaptures(prev => [{ ...msg, time: now() }, ...prev]); setScore(s => Math.max(0, s - 40)) }
    }
    ws.onclose = () => setTimeout(connectWs, 2000)
  }, [])

  useEffect(() => { connectWs(); return () => wsRef.current?.close() }, [connectWs])

  // ── Scan (auto-detects interface) ────────────────────────────────────
  const handleScan = async () => {
    setScanning(true)
    setScanResult(null)
    setSelectedTarget(null)
    try {
      const r = await fetch(`${API}/scan`)
      const data = await r.json()
      setScanResult(data)
      setSniffing(true)
      if (data.gateway_ip && data.gateway_mac) {
        await fetch(`${API}/golden-table`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: data.gateway_ip, mac: data.gateway_mac }) })
        fetchGoldenTable()
      }
    } catch (err) { console.error(err) }
    finally { setScanning(false) }
  }

  const handleStop = async () => {
    await fetch(`${API}/stop`, { method: 'POST' })
    await fetch(`${API}/attack/stop`, { method: 'POST' })
    await fetch(`${API}/dns/stop`, { method: 'POST' })
    await fetch(`${API}/phish/stop`, { method: 'POST' })
    setSniffing(false); setScanResult(null); setSelectedTarget(null)
    setAttacking(false); setDnsActive(false); setPhishActive(false); setScore(100)
  }

  const toggleProtect = async () => {
    const next = !protect
    await fetch(`${API}/protect`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: next }) })
    setProtect(next)
  }

  const handleAttack = async (target, gateway) => {
    if (!gateway) return
    await fetch(`${API}/attack/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_ip: target.ip, target_mac: target.mac, gateway_ip: gateway.ip, gateway_mac: gateway.mac }) })
  }

  const handleStopAttack = async () => {
    await fetch(`${API}/attack/stop`, { method: 'POST' })
    if (dnsActive) { await fetch(`${API}/dns/stop`, { method: 'POST' }); setDnsActive(false) }
  }

  const toggleDns = async () => {
    if (!dnsActive) {
      await fetch(`${API}/dns/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_ip: selectedTarget.ip, redirect_ip: scanResult.ip }) })
      setDnsActive(true)
    } else { await fetch(`${API}/dns/stop`, { method: 'POST' }); setDnsActive(false) }
  }

  const togglePhish = async () => {
    if (!phishActive) {
      await fetch(`${API}/phish/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ port: phishPort }) })
      setPhishActive(true)
    } else { await fetch(`${API}/phish/stop`, { method: 'POST' }); setPhishActive(false) }
  }

  const [vpnBlocked, setVpnBlocked] = useState(false)

  const demoSimulateCapture = () => {
    setVpnBlocked(false)
    setPhishCaptures(prev => [{
      src_ip: '172.20.10.3',
      time: now(),
      creds: { email: 'victim@gmail.com', password: 'qwerty123' }
    }, ...prev])
    setScore(s => Math.max(0, s - 40))
  }

  const demoSimulateVpn = () => {
    setVpnBlocked(true)
    setScore(100)
  }

  const gateway = scanResult ? { ip: scanResult.gateway_ip, mac: scanResult.gateway_mac } : null
  const localInfo = scanResult ? { ip: scanResult.ip, mac: scanResult.mac } : null

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: '24px 16px', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}`}</style>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>ARP Guard</h1>
          <div style={{ fontSize: 12, color: '#4a5568' }}>ARP Spoofing Detection &amp; Prevention</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <SecurityScore score={score} />
          <StatusBanner alerts={alerts} />
        </div>
      </div>

      {/* Controls */}
      <div style={{ background: '#161922', borderRadius: 10, padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        {!sniffing
          ? <button onClick={handleScan} disabled={scanning} style={{ background: '#276749', color: '#fff', minWidth: 160, fontSize: 15, padding: '10px 20px' }}>
              {scanning ? '⏳ Scanning…' : '🔍 Scan Network'}
            </button>
          : <>
              <button onClick={handleScan} disabled={scanning} style={{ background: '#2c5282', color: '#fff', minWidth: 140 }}>
                {scanning ? '⏳ Scanning…' : '🔄 Rescan'}
              </button>
              <button onClick={handleStop} style={{ background: '#742a2a', color: '#fff', minWidth: 100 }}>⏹ Stop</button>
            </>
        }
        {sniffing && (
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 13, color: '#718096' }}>IPS Protection</span>
            <button onClick={toggleProtect} style={{ background: protect ? '#d69e2e' : '#2d3348', color: protect ? '#1a1000' : '#a0aec0', minWidth: 90 }}>
              {protect ? '🛡 ON' : '🛡 OFF'}
            </button>
          </div>
        )}
      </div>

      {/* Attack tools */}
      <div style={{ background: '#161922', borderRadius: 10, padding: '12px 18px', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 12, color: '#718096', textTransform: 'uppercase', letterSpacing: 1 }}>Attack Tools</span>

        {attacking && selectedTarget && (
          <button onClick={toggleDns} style={{ background: dnsActive ? '#6b46c1' : '#322659', color: dnsActive ? '#fff' : '#a0aec0', minWidth: 130 }}>
            {dnsActive ? '🌀 DNS ON' : '🌀 DNS Spoof'}
          </button>
        )}

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="number" value={phishPort} onChange={e => setPhishPort(Number(e.target.value))} disabled={phishActive}
            style={{ width: 70, padding: '4px 8px', background: '#0f1117', border: '1px solid #2d3748', color: '#e2e8f0', borderRadius: 4, fontSize: 13 }} />
          <button onClick={togglePhish} style={{ background: phishActive ? '#c05621' : '#7b341e', color: '#fff', minWidth: 140 }}>
            {phishActive ? `🎣 Phish :${phishPort} ON` : '🎣 Start Phish Page'}
          </button>
        </div>

        {phishActive && (
          <span style={{ fontSize: 12, color: '#68d391', fontFamily: 'monospace' }}>
            → http://{localInfo?.ip || 'your-ip'}:{phishPort}
          </span>
        )}
      </div>

      <BitrateChart data={bitrateData} />
      <PacketMap attacking={attacking} victim={selectedTarget} localInfo={localInfo} gateway={gateway} />

      {scanResult && (
        <DeviceList devices={scanResult.devices} gateway={gateway} selectedTarget={selectedTarget}
          onSelect={setSelectedTarget} attacking={attacking} onAttack={handleAttack} onStopAttack={handleStopAttack} />
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <GoldenTable table={goldenTable} onRefresh={fetchGoldenTable} />
        <AlertLog alerts={alertLog} />
      </div>

      {dnsSpoofed.length > 0 && (
        <div style={{ background: '#161922', borderRadius: 10, padding: '14px 18px' }}>
          <div style={{ fontSize: 12, color: '#718096', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 }}>DNS Spoof Log</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 160, overflowY: 'auto' }}>
            {dnsSpoofed.map((d, i) => <div key={i} style={{ fontSize: 12, fontFamily: 'monospace', color: '#b794f4' }}>{d.time} &nbsp; {d.domain} → {d.redirected_to}</div>)}
          </div>
        </div>
      )}

      {phishCaptures.length > 0 && (
        <div style={{ background: '#1a0a00', border: '1px solid #c05621', borderRadius: 10, padding: '14px 18px' }}>
          <div style={{ fontSize: 12, color: '#ed8936', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 }}>🎣 Phished Credentials ({phishCaptures.length})</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 240, overflowY: 'auto' }}>
            {phishCaptures.map((p, i) => (
              <div key={i} style={{ background: '#2d1200', border: '1px solid #9c4221', borderRadius: 6, padding: '8px 12px' }}>
                <div style={{ fontSize: 11, color: '#718096', marginBottom: 4 }}>{p.src_ip} &nbsp;|&nbsp; {p.time}</div>
                {Object.entries(p.creds).map(([k, v]) => (
                  <div key={k} style={{ fontFamily: 'monospace', fontSize: 13 }}>
                    <span style={{ color: '#ed8936', fontWeight: 700 }}>{k}</span>
                    <span style={{ color: '#718096' }}> = </span>
                    <span style={{ color: '#fff', fontWeight: 700 }}>{v}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      <HttpCapture packets={httpPackets} />

      {/* Demo Mode */}
      <div style={{ background: '#161922', border: '1px solid #2d3748', borderRadius: 10, padding: '14px 18px' }}>
        <div style={{ fontSize: 12, color: '#718096', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>🎭 Demo Mode</div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <button onClick={demoSimulateCapture} style={{ background: '#742a2a', color: '#fff', padding: '10px 20px', borderRadius: 6, border: 'none', cursor: 'pointer', fontWeight: 600 }}>
            ⚠️ Simulate Attack (No VPN)
          </button>
          <button onClick={demoSimulateVpn} style={{ background: '#1a4731', color: '#68d391', padding: '10px 20px', borderRadius: 6, border: '1px solid #276749', cursor: 'pointer', fontWeight: 600 }}>
            🛡 Simulate VPN Protection
          </button>
        </div>
        {vpnBlocked && (
          <div style={{ marginTop: 14, background: '#0d2b1a', border: '1px solid #276749', borderRadius: 8, padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 28 }}>🛡</span>
            <div>
              <div style={{ color: '#68d391', fontWeight: 700, fontSize: 16 }}>VPN PROTECTED — Credentials Blocked</div>
              <div style={{ color: '#4a5568', fontSize: 13, marginTop: 4 }}>DNS queries are routed through the encrypted VPN tunnel. DNS spoofing has no effect.</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
