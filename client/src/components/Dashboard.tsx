import React, { useEffect, useMemo, useRef, useState } from 'react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, LineChart, Line, Legend
} from 'recharts'
import { useNavigate } from 'react-router-dom'

// ---- THEME ----
const LOGO = 'https://xcapitalgrp.com/wp-content/uploads/2024/09/xc-resized.png'
const COLORS_OK_BAD = ['#22c55e', '#ef4444']
const BRAND = { aws: '#2563eb', az: '#9333ea' }
const C = {
  bg: '#0b0f19',
  card: '#111827',
  primary: '#0ea5e9',
  accent: '#fbbf24',
  muted: '#94a3b8',
  ok: '#22c55e',
  warn: '#f97316',
  bad: '#ef4444',
  chip: {
    iso: '#6366f1',
    sox: '#f59e0b',
    nist: '#0ea5e9',
  }
}

// ---- TYPES ----
export type Provider = 'AWS' | 'Azure'
export type ProviderFilter = Provider | 'ALL'

export type ResourceRow = {
  provider: Provider
  type: string
  id: string
  status: 'Compliant' | 'Non-Compliant'
  framework?: string | string[]
}

export type ComplianceSummary = {
  totalResources: number
  compliant: number
  nonCompliant: number
  bySeverity: { critical: number; high: number; medium: number; low: number }
  byProvider: { AWS: number; Azure: number }
  resources: ResourceRow[]
  demo?: boolean
}

export type AlertItem = {
  id: string
  provider: Provider
  resource: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  time: string
}

type RiskRecord = {
  id: string | number
  subject: string
  severity?: string
  status?: string
  created?: string
  frameworks?: string[] // for badges
}

// ---- API HELPERS ----
const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:4000'

function authHeaders() {
  const token = localStorage.getItem('xcap_token')
  return {
    Authorization: token ? `Bearer ${token}` : '',
    'Content-Type': 'application/json',
  }
}

async function fetchSummary(provider: ProviderFilter): Promise<ComplianceSummary> {
  const url = `${API_BASE}/api/summary?provider=${encodeURIComponent(provider)}`
  const res = await fetch(url, { headers: authHeaders() })
  if (!res.ok) throw new Error(`summary ${res.status}`)
  return await res.json()
}

async function fetchAlerts(provider: ProviderFilter): Promise<AlertItem[]> {
  const url = `${API_BASE}/api/alerts?provider=${encodeURIComponent(provider)}`
  const res = await fetch(url, { headers: authHeaders() })
  if (!res.ok) throw new Error(`alerts ${res.status}`)
  return await res.json()
}

async function fetchSimpleRiskRisks(): Promise<RiskRecord[]> {
  const res = await fetch(`${API_BASE}/api/simplerisk/risks`, { headers: authHeaders() })
  if (!res.ok) throw new Error(`risks ${res.status}`)
  const data = await res.json()

  // Normalize + attach guessed frameworks from subject text if present
  const normalize = (r: any): RiskRecord => {
    const subject: string = r.subject || r.title || 'Unknown Risk'
    const fx: string[] = []
    if (/iso\s*27001/i.test(subject)) fx.push('ISO 27001')
    if (/sox/i.test(subject)) fx.push('SOX 404')
    if (/nist/i.test(subject) || /800-53/i.test(subject)) fx.push('NIST 800-53')
    return {
      id: r.id || crypto.randomUUID(),
      subject,
      severity: r.severity || 'Medium',
      status: r.status || 'New',
      created: r.created || new Date().toISOString(),
      frameworks: r.frameworks || fx
    }
  }

  return Array.isArray(data) ? data.map(normalize) : []
}

// ---- UTIL (client-side demo extras) ----
type TrendPoint = { date: string; compliant: number; nonCompliant: number }
type HeatCell = { severity: 'Critical' | 'High' | 'Medium' | 'Low'; likelihood: 'Low' | 'Medium' | 'High'; count: number }

function makeDemoTrend(summary?: ComplianceSummary): TrendPoint[] {
  // simulate a week movement anchored to current summary
  const baseC = summary?.compliant ?? 12
  const baseNC = summary?.nonCompliant ?? 9
  const days = 7
  const out: TrendPoint[] = []
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 24 * 3600 * 1000)
    const jitterC = Math.max(0, baseC + Math.round((Math.random() - 0.5) * 4))
    const jitterNC = Math.max(0, baseNC + Math.round((Math.random() - 0.5) * 4))
    out.push({ date: d.toLocaleDateString(), compliant: jitterC, nonCompliant: jitterNC })
  }
  return out
}

function makeDemoHeatmap(summary?: ComplianceSummary): HeatCell[] {
  // spread non-compliant into a 3x4 grid (likelihood x severity)
  const totalNC = summary?.nonCompliant ?? 9
  const buckets: HeatCell[] = []
  const sev: HeatCell['severity'][] = ['Critical', 'High', 'Medium', 'Low']
  const lik: HeatCell['likelihood'][] = ['Low', 'Medium', 'High']

  let remaining = totalNC
  for (const l of lik) {
    for (const s of sev) {
      const slice = Math.max(0, Math.round((Math.random() * remaining) / (sev.length * lik.length / 1.5)))
      buckets.push({ severity: s, likelihood: l, count: slice })
      remaining -= slice
    }
  }
  // distribute leftovers
  let i = 0
  while (remaining > 0) {
    buckets[i % buckets.length].count++
    remaining--
    i++
  }
  return buckets
}

// ---- UI ATOMS ----
function ProviderToggle({ value, onChange }: { value: ProviderFilter; onChange: (p: ProviderFilter) => void }) {
  const opt = (v: ProviderFilter, label: string) => (
    <button
      onClick={() => onChange(v)}
      style={{
        padding: '8px 12px',
        borderRadius: 10,
        border: '1px solid #1f2937',
        background: value === v ? 'rgba(14,165,233,.15)' : 'transparent',
        color: value === v ? '#fff' : C.muted,
        fontSize: 12,
      }}
    >
      {label}
    </button>
  )
  return <div style={{ display: 'flex', gap: 8 }}>{opt('ALL', 'ALL')}{opt('AWS', 'AWS')}{opt('Azure', 'Azure')}</div>
}

function KpiCard({ label, value, tone = 'info', delta, onClick }: {
  label: string; value: React.ReactNode; tone?: 'info' | 'ok' | 'bad' | 'warn'; delta?: string; onClick?: () => void
}) {
  const toneBg = tone === 'ok' ? 'rgba(34,197,94,.12)' : tone === 'bad' ? 'rgba(239,68,68,.12)' : tone === 'warn' ? 'rgba(251,191,36,.12)' : 'rgba(14,165,233,.12)'
  const toneColor = tone === 'ok' ? C.ok : tone === 'bad' ? C.bad : tone === 'warn' ? C.accent : C.primary
  return (
    <div onClick={onClick} style={{ cursor: onClick ? 'pointer' : 'default', border: '1px solid #1f2937', background: C.card, borderRadius: 16, padding: 16 }}>
      <div style={{ color: C.muted, fontSize: 12 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, marginTop: 6 }}>{value}</div>
      {delta && <div style={{ marginTop: 8, fontSize: 12, color: toneColor, background: toneBg, display: 'inline-block', padding: '2px 8px', borderRadius: 6 }}>{delta}</div>}
    </div>
  )
}

function Donut({ data }: { data: { name: string; value: number }[] }) {
  const donutColors: Record<string, string> = { Compliant: C.ok, 'Non-Compliant': C.bad }
  const total = data.reduce((s, d) => s + d.value, 0)
  const tooltipFormatter = (value: any, name: any) => `${name}: ${value} (${total ? ((value / total) * 100).toFixed(1) : '0.0'}%)`
  return (
    <div style={{ width: '100%', height: 256 }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={70} outerRadius={100} paddingAngle={3} isAnimationActive animationDuration={800} animationEasing="ease-in-out">
            {data.map((entry, i) => (
              <Cell key={i} fill={donutColors[entry.name] || COLORS_OK_BAD[i % COLORS_OK_BAD.length]} />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}

function BarSimple({ data }: { data: { name: string; value: number }[] }) {
  const total = data.reduce((s, d) => s + d.value, 0)
  const tooltipFormatter = (v: number) => `${v} (${total ? ((v / total) * 100).toFixed(1) : '0.0'}%)`
  return (
    <div style={{ width: '100%', height: 256 }}>
      <ResponsiveContainer>
        <BarChart data={data} barCategoryGap={20}>
          <XAxis dataKey="name" stroke={C.muted} />
          <YAxis stroke={C.muted} />
          <Tooltip formatter={tooltipFormatter as any} />
          <Bar dataKey="value" isAnimationActive animationDuration={800} animationEasing="ease-in-out">
            {data.map((entry, index) => {
              const colorMap: Record<string, string> = {
                Critical: '#E63946',  // red
                High: '#F77F00',      // orange
                Medium: '#F2C94C',    // yellow
                Low: '#2A9D8F',       // greenish
                AWS: '#FF9900',       // AWS orange
                Azure: '#0078D7'      // Azure blue
              };
              return <Cell key={`cell-${index}`} fill={colorMap[entry.name] || '#1D4ED8'} />;
            })}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}


function AlertsFeed({ items }: { items: AlertItem[] }) {
  return (
    <div style={{ color: C.muted, fontSize: 14 }}>
      {items.length === 0 ? (
        <div>No alerts</div>
      ) : (
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {items.map((a) => (
            <li key={a.id} style={{ marginBottom: 12, padding: 12, borderRadius: 8, background: 'rgba(239,68,68,0.1)' }}>
              <div style={{ fontWeight: 600, color: a.severity === 'critical' ? C.bad : C.warn }}>{a.title}</div>
              <div style={{ fontSize: 12, color: C.muted }}>{a.provider} • {a.resource}</div>
              <div style={{ fontSize: 12, color: '#64748b' }}>{new Date(a.time).toLocaleString()}</div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function FrameworkChips({ frameworks }: { frameworks?: string[] }) {
  if (!frameworks || frameworks.length === 0) return null
  const color = (fw: string) =>
    /iso/i.test(fw) ? C.chip.iso :
    /sox/i.test(fw) ? C.chip.sox :
    /nist/i.test(fw) ? C.chip.nist : '#475569'
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
      {frameworks.map((fw, i) => (
        <span key={i} style={{ fontSize: 11, color: '#fff', background: color(fw), padding: '2px 8px', borderRadius: 999 }}>
          {fw}
        </span>
      ))}
    </div>
  )
}

// ---- MAIN DASHBOARD ----
export default function XCapitalDashboard() {
  const [provider, setProvider] = useState<ProviderFilter>('ALL')
  const [summary, setSummary] = useState<ComplianceSummary | null>(null)
  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [risks, setRisks] = useState<RiskRecord[]>([])
  const [filter, setFilter] = useState<{ status: 'Compliant' | 'Non-Compliant' | null; severity: 'Critical' | 'High' | 'Medium' | 'Low' | null }>({ status: null, severity: null })
  const [loading, setLoading] = useState(false)
  const [srLoading, setSrLoading] = useState(false)
  const [demoMode, setDemoMode] = useState(false)
  const [trendData, setTrendData] = useState<TrendPoint[]>([])
  const [heatmap, setHeatmap] = useState<HeatCell[]>([])
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('xcap_user') || '{}')
  const pollRef = useRef<number | null>(null)

  // Export
  const exportReport = async () => {
    const res = await fetch(`${API_BASE}/api/export/pdf`, { headers: authHeaders() })
    if (!res.ok) return alert('Failed to generate PDF')
    const blob = await res.blob()
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'XCapital_Compliance_Report.pdf'
    a.click()
    window.URL.revokeObjectURL(url)
  }

  // Loaders
  const load = async () => {
    setLoading(true)
    try {
      const [s, a] = await Promise.all([fetchSummary(provider), fetchAlerts(provider)])
      setSummary(s)
      setAlerts(a)
      // demo detection: server may add demo flag, else infer by balanced counts typical of seed
      const isDemo = Boolean((s as any)?.demo) || (s.totalResources >= 15 && s.totalResources <= 40 && s.byProvider.AWS > 0 && s.byProvider.Azure > 0)
      setDemoMode(isDemo)
    } catch (e) {
      console.error('Data fetch error', e)
    } finally {
      setLoading(false)
    }
  }

  const loadRiskRegister = async () => {
    setSrLoading(true)
    try {
      const r = await fetchSimpleRiskRisks()
      setRisks(r)
    } catch (e) {
      console.error('risk fetch', e)
    } finally {
      setSrLoading(false)
    }
  }

  // Extras (trend + heatmap): try API, fallback to mock
  const loadExtras = async () => {
    let trendOk = false
    let heatOk = false
    try {
      const res = await fetch(`${API_BASE}/api/trends`, { headers: authHeaders() })
      if (res.ok) {
        const t = await res.json()
        if (Array.isArray(t) && t.length) {
          setTrendData(t)
          trendOk = true
        }
      }
    } catch {}
    try {
      const res = await fetch(`${API_BASE}/api/heatmap`, { headers: authHeaders() })
      if (res.ok) {
        const h = await res.json()
        if (Array.isArray(h) && h.length) {
          setHeatmap(h)
          heatOk = true
        }
      }
    } catch {}

    // Fallbacks in demo/no API
    if (!trendOk) setTrendData(makeDemoTrend(summary || undefined))
    if (!heatOk) setHeatmap(makeDemoHeatmap(summary || undefined))
  }

  useEffect(() => { load(); loadRiskRegister(); }, [provider])

  useEffect(() => { loadExtras() }, [summary?.totalResources])

  useEffect(() => {
    if (pollRef.current) window.clearInterval(pollRef.current)
    pollRef.current = window.setInterval(async () => {
      await load()
      await loadRiskRegister()
    }, 120000)
    return () => { if (pollRef.current) window.clearInterval(pollRef.current) }
  }, [provider])

  const logout = () => {
    localStorage.removeItem('xcap_token')
    localStorage.removeItem('xcap_user')
    navigate('/login')
  }

  // Derived data
  const filteredResources = useMemo(() => {
    const list = summary?.resources ?? []
    return list.filter(r => {
      const pOK = provider === 'ALL' ? true : r.provider === provider
      const sOK = filter.status ? r.status === filter.status : true
      return pOK && sOK
    })
  }, [summary, provider, filter])

  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const pOK = provider === 'ALL' ? true : a.provider === provider
      const sevOK = filter.severity ? a.severity.toLowerCase() === filter.severity!.toLowerCase() : true
      return pOK && sevOK
    })
  }, [alerts, provider, filter])

  const donutData = useMemo(() => {
    const compliant = filteredResources.filter(r => r.status === 'Compliant').length
    const non = filteredResources.filter(r => r.status === 'Non-Compliant').length
    return [{ name: 'Compliant', value: compliant }, { name: 'Non-Compliant', value: non }]
  }, [filteredResources])

  const severityData = useMemo(() => {
    const agg = { Critical: 0, High: 0, Medium: 0, Low: 0 }
    filteredAlerts.forEach(a => {
      const key = a.severity.charAt(0).toUpperCase() + a.severity.slice(1) as keyof typeof agg
      agg[key]++
    })
    return Object.entries(agg).map(([name, value]) => ({ name, value }))
  }, [filteredAlerts])

  const providerData = useMemo(() => {
    if (filter.status) {
      const counts = { AWS: 0, Azure: 0 }
      filteredResources.forEach(r => { counts[r.provider]++ })
      return [{ name: 'AWS', value: counts.AWS }, { name: 'Azure', value: counts.Azure }]
    }
    return summary ? [{ name: 'AWS', value: summary.byProvider.AWS }, { name: 'Azure', value: summary.byProvider.Azure }] : []
  }, [summary, filteredResources, filter])

  // UI
  return (
    <div style={{ minHeight: '100vh', background: C.bg, color: '#fff' }}>
      <header style={{ position: 'sticky', top: 0, zIndex: 10, backdropFilter: 'blur(6px)', background: 'rgba(11,15,25,0.8)', borderBottom: '1px solid #1f2937' }}>
        <div style={{ maxWidth: 1120, margin: '0 auto', padding: '16px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <img src={LOGO} alt="XCapital" style={{ height: 32 }} />
            <div style={{ fontSize: 18, fontWeight: 600 }}>XCapital – Multi-Cloud GRC & Audit</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {demoMode && (
              <div style={{ fontSize: 12, color: '#facc15', background: 'rgba(234,179,8,0.1)', padding: '4px 10px', borderRadius: 6 }}>
                Demo Data Active
              </div>
            )}
            <button
              onClick={exportReport}
              style={{ background: 'rgba(14,165,233,0.15)', border: '1px solid #0ea5e9', color: '#fff', fontSize: 12, padding: '6px 10px', borderRadius: 8, cursor: 'pointer' }}
            >
              📄 Export Report
            </button>

              {/* Admin-only User Management button */}
              {user.role === 'admin' && (
                <button
                onClick={() => navigate('/admin/users')}
                style={{ background: 'rgba(34,197,94,0.15)', border: '1px solid #22c55e', color: '#fff', fontSize: 12, padding: '6px 10px', borderRadius: 8, cursor: 'pointer' }}
                >
                  👥 Manage Users
                  </button>
              )}

            <div style={{ fontSize: 13, color: C.muted }}>Welcome, <strong>{user?.email?.split('@')[0]}</strong> ({user?.role || 'Analyst'})</div>
            <button onClick={logout} style={{ background: 'rgba(239,68,68,.15)', border: '1px solid #ef4444', color: '#fff', fontSize: 12, padding: '6px 10px', borderRadius: 8, cursor: 'pointer' }}>👤 Logout</button>
          </div>
        </div>
      </header>

      <main style={{ maxWidth: 1120, margin: '0 auto', padding: '24px' }}>
        {/* Top notice for high severity */}
        {filteredAlerts.some(a => ['critical', 'high'].includes(a.severity)) && (
          <div style={{ border: '1px solid rgba(239,68,68,.3)', background: 'rgba(239,68,68,.1)', borderRadius: 16, padding: 16, marginBottom: 16 }}>
            <div style={{ fontWeight: 600 }}>New high-severity findings detected</div>
            <div style={{ fontSize: 14, color: C.muted }}>Review and triage immediately.</div>
          </div>
        )}

        {/* Toolbar */}
        <div style={{ marginBottom: 16, display: 'flex', gap: 12, alignItems: 'center', justifyContent: 'space-between' }}>
          <ProviderToggle value={provider} onChange={setProvider} />
          {(filter.status || filter.severity) && (
            <button onClick={() => setFilter({ status: null, severity: null })} style={{ fontSize: 12, color: '#fff', background: 'rgba(14,165,233,.15)', border: '1px solid #1f2937', padding: '6px 10px', borderRadius: 8 }}>
              Clear Filters
            </button>
          )}
        </div>

        {/* KPI */}
        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
          <KpiCard label="Total Resources" value={filteredResources.length} delta={provider} tone="info" />
          <KpiCard label="Compliant" value={filteredResources.filter(r => r.status === 'Compliant').length} tone="ok" onClick={() => setFilter({ status: 'Compliant', severity: null })} />
          <KpiCard label="Non-Compliant" value={filteredResources.filter(r => r.status === 'Non-Compliant').length} tone="bad" onClick={() => setFilter({ status: 'Non-Compliant', severity: null })} />
          <KpiCard label="Critical / High" value={`${severityData[0]?.value ?? 0} / ${severityData[1]?.value ?? 0}`} tone="warn" />
        </section>

        {/* CHARTS */}
        <section style={{ marginTop: 24, display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
          <div style={{ border: '1px solid #1f2937', background: C.card, borderRadius: 16, padding: 16 }}>
            <div style={{ color: C.muted, fontSize: 12, marginBottom: 8 }}>Compliance Ratio</div>
            <Donut data={donutData} />
          </div>
          <div style={{ border: '1px solid #1f2937', background: C.card, borderRadius: 16, padding: 16 }}>
            <div style={{ color: C.muted, fontSize: 12, marginBottom: 8 }}>Findings by Severity</div>
            <BarSimple data={severityData} />
          </div>
          <div style={{ border: '1px solid #1f2937', background: C.card, borderRadius: 16, padding: 16 }}> 
  <div style={{ color: C.muted, fontSize: 12, marginBottom: 8 }}>Resources by Provider</div>

  <div style={{ width: '100%', height: 256 }}>
    <ResponsiveContainer>
      <BarChart data={providerData}>
        <XAxis dataKey="name" stroke={C.muted} />
        <YAxis stroke={C.muted} />
        <Tooltip />

        <Bar dataKey="value" isAnimationActive animationDuration={800} animationEasing="ease-in-out">
          {providerData.map((entry, index) => {
            const colorMap: Record<string, string> = {
              AWS: '#F7931A',   // AWS orange
              Azure: '#0078D4', // Azure blue
            };
            return (
              <Cell 
                key={`cell-${index}`} 
                fill={colorMap[entry.name] || '#64748b'} 
              />
            );
          })}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  </div>
</div>       
        </section>

        {/* NEW ANALYTICS ROW: Trend + Heatmap */}
        <section style={{ marginTop: 24, display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
          <div style={{ border: '1px solid #1f2937', background: C.card, borderRadius: 16, padding: 16 }}>
            <div style={{ color: C.muted, fontSize: 12, marginBottom: 8 }}>Compliance Trend (7 Days)</div>
            <div style={{ width: '100%', height: 250 }}>
              <ResponsiveContainer>
                <LineChart data={trendData}>
                  <XAxis dataKey="date" stroke={C.muted} />
                  <YAxis stroke={C.muted} />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="compliant" stroke={C.ok} />
                  <Line type="monotone" dataKey="nonCompliant" stroke={C.bad} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div style={{ border: '1px solid #1f2937', background: C.card, borderRadius: 16, padding: 16 }}>
            <div style={{ color: C.muted, fontSize: 12, marginBottom: 8 }}>Risk Heatmap</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8 }}>
              {heatmap.map((c, i) => (
                <div key={i} style={{
                  background:
                  c.count === 0 ? '#334155' : // gray for empty
                  /critical/i.test(c.severity) ? '#E63946' : // red
                  /high/i.test(c.severity) ? '#F77F00' : // orange
                  /medium/i.test(c.severity) ? '#F2C94C' : // yellow
                  /low/i.test(c.severity) ? '#2A9D8F' : // green
                  '#475569',
                }}>
                  <div style={{ fontWeight: 700 }}>{c.count}</div>
                  <div style={{ fontSize: 12, color: '#d1d5db' }}>{c.severity} / {c.likelihood}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ALERTS + RESOURCES */}
        <section style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 16, marginTop: 24 }}>
          <div style={{ border: '1px solid #1f2937', background: C.card, borderRadius: 16, padding: 16 }}>
            <div style={{ color: C.muted, fontSize: 12, marginBottom: 12 }}>Recent Alerts</div>
            {loading ? <div style={{ color: C.muted }}>Loading…</div> : <AlertsFeed items={filteredAlerts} />}
          </div>
          <div style={{ border: '1px solid #1f2937', background: C.card, borderRadius: 16, padding: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: C.muted, fontSize: 12, marginBottom: 12 }}>
              <span>Resources</span>
              {(filter.status || filter.severity) && (
                <button onClick={() => setFilter({ status: null, severity: null })} style={{ fontSize: 12, color: '#fff', background: 'rgba(14,165,233,.15)', border: '1px solid #1f2937', padding: '2px 8px', borderRadius: 6 }}>
                  Clear Filters
                </button>
              )}
            </div>
            <div style={{ maxHeight: 300, overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ color: C.muted, borderBottom: '1px solid #1f2937' }}>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Provider</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Type</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>ID</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Status</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Framework</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredResources.map((r, i) => {
                    const isNC = r.status === 'Non-Compliant'
                    const fw = Array.isArray(r.framework) ? r.framework : (r.framework ? [r.framework] : [])
                    return (
                      <tr key={`${r.id}-${i}`} style={{ borderBottom: '1px solid #1f2937' }}>
                        <td style={{ padding: '6px 8px', color: r.provider === 'AWS' ? BRAND.aws : BRAND.az }}>{r.provider}</td>
                        <td style={{ padding: '6px 8px' }}>{r.type}</td>
                        <td style={{ padding: '6px 8px' }}>{r.id}</td>
                        <td style={{ padding: '6px 8px', color: isNC ? C.bad : C.ok }}>{r.status}</td>
                        <td style={{ padding: '6px 8px' }}>
                          {fw.length === 0 ? <span style={{ color: C.muted }}>—</span> : (
                            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                              {fw.map((f, idx) => (
                                <span key={idx} style={{
                                  fontSize: 11, color: '#fff',
                                  background:
                                    /iso/i.test(f) ? C.chip.iso :
                                    /sox/i.test(f) ? C.chip.sox :
                                    /nist/i.test(f) ? C.chip.nist : '#475569',
                                  padding: '2px 8px', borderRadius: 999
                                }}>{f}</span>
                              ))}
                            </div>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* RISK REGISTER */}
        <section style={{ marginTop: 24 }}>
          <div style={{ border: '1px solid #1f2937', background: C.card, borderRadius: 16, padding: 16 }}>
            <div style={{ color: C.muted, fontSize: 12, marginBottom: 8 }}>XRisk Intelligence powered by SimpleRisk ({srLoading ? 'loading…' : `${risks.length}`})</div>
            <div style={{ maxHeight: 320, overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ color: C.muted, borderBottom: '1px solid #1f2937' }}>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>ID</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Subject</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Severity</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Status</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Frameworks</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {risks.length === 0 ? (
                    <tr><td colSpan={6} style={{ padding: '10px 8px', color: C.muted }}>No open risks</td></tr>
                  ) : (
                    risks.map((r) => (
                      <tr key={String(r.id)} style={{ borderBottom: '1px solid #1f2937' }}>
                        <td style={{ padding: '6px 8px' }}>{r.id}</td>
                        <td style={{ padding: '6px 8px' }}>{r.subject}</td>
                        <td style={{ padding: '6px 8px', color: (r.severity || '').toLowerCase() === 'critical' ? C.bad : (r.severity || '').toLowerCase() === 'high' ? C.warn : C.muted }}>{r.severity || '-'}</td>
                        <td style={{ padding: '6px 8px' }}>{r.status || '-'}</td>
                        <td style={{ padding: '6px 8px' }}><FrameworkChips frameworks={r.frameworks} /></td>
                        <td style={{ padding: '6px 8px' }}>{r.created ? new Date(r.created).toLocaleString() : '-'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}
