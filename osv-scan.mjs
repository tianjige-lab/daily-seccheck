// osv-scan.mjs - zero-model lookup of package-lock.json name@version pairs against OSV (includes GitHub Advisory and the OSSF malicious-package set, ids MAL-).
// Usage:  node osv-scan.mjs <label1>=<lock1.json> [<label2>=<lock2.json> ...] [--min-severity HIGH]
// Output: { scanned, findings: [{ id, kind, pkg, ver, severity, labels, prod }] } as JSON on stdout.
//         kind = malware | advisory ; prod = true when at least one lock file lists the package as a non-dev dependency.
// Only package names and versions are sent to the OSV API.
import fs from 'node:fs'
const args = process.argv.slice(2)
let minSev = 'HIGH'
const locks = []
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--min-severity') { minSev = args[++i]; continue }
  const eq = args[i].indexOf('=')
  if (eq < 1) { console.log(JSON.stringify({ error: 'bad-argument', scanned: 0, findings: [] })); process.exit(2) }
  locks.push({ label: args[i].slice(0, eq), file: args[i].slice(eq + 1) })
}
const RANK = { LOW: 1, MODERATE: 2, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }
const pk = new Map() // key name@ver -> { name, ver, labels:Set, prod:boolean }
for (const { label, file } of locks) {
  const j = JSON.parse(fs.readFileSync(file, 'utf8'))
  const add = (name, ver, dev) => {
    if (!name || !ver) return
    const k = `${name}@${ver}`
    const e = pk.get(k) ?? { name, ver, labels: new Set(), prod: false }
    e.labels.add(label); if (!dev) e.prod = true; pk.set(k, e)
  }
  if (j.packages) for (const [p, m] of Object.entries(j.packages)) { if (p) add(m.name ?? p.split('node_modules/').pop(), m.version, m.dev === true) }
  else { const walk = (d) => { for (const [n, m] of Object.entries(d ?? {})) { add(n, m.version, m.dev === true); walk(m.dependencies) } }; walk(j.dependencies) }
}
const items = [...pk.values()]
const hits = new Map() // key -> [ids]
const fail = (code) => { console.log(JSON.stringify({ error: code, scanned: items.length, findings: [] })); process.exit(3) }
try {
  for (let i = 0; i < items.length; i += 500) {
    const chunk = items.slice(i, i + 500)
    const res = await (await fetch('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries: chunk.map((e) => ({ package: { name: e.name, ecosystem: 'npm' }, version: e.ver })) }), signal: AbortSignal.timeout(120000) })).json()
    chunk.forEach((e, idx) => { const v = res.results?.[idx]?.vulns; if (v?.length) hits.set(`${e.name}@${e.ver}`, v.map((x) => x.id)) })
  }
} catch { fail('osv-api-unreachable') }
const cache = new Map()
const detail = async (id) => { if (cache.has(id)) return cache.get(id); const d = await (await fetch('https://api.osv.dev/v1/vulns/' + encodeURIComponent(id), { signal: AbortSignal.timeout(60000) })).json(); cache.set(id, d); return d }
const findings = []
for (const [key, ids] of hits) {
  const e = pk.get(key)
  for (const id of ids) {
    if (id.startsWith('MAL-')) { findings.push({ id, kind: 'malware', pkg: e.name, ver: e.ver, severity: 'CRITICAL', labels: [...e.labels], prod: e.prod }); continue }
    let d; try { d = await detail(id) } catch { fail('osv-api-unreachable') }
    const sev = String(d.database_specific?.severity ?? 'UNKNOWN').toUpperCase()
    const malwareWording = /malware|malicious package|compromised (package|version)/i.test(d.summary ?? '')
    if (malwareWording) { findings.push({ id, kind: 'malware', pkg: e.name, ver: e.ver, severity: 'CRITICAL', labels: [...e.labels], prod: e.prod }); continue }
    if ((RANK[sev] ?? 0) >= (RANK[minSev] ?? 3)) findings.push({ id, kind: 'advisory', pkg: e.name, ver: e.ver, severity: sev, labels: [...e.labels], prod: e.prod })
  }
}
console.log(JSON.stringify({ scanned: items.length, findings }))
