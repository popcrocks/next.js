// A loopback "internal-only" service that stands in for something an internet-
// facing Next server must NEVER be able to reach from user input — a cloud
// metadata endpoint, an internal admin panel, a private object store, etc.
// It returns a per-path "secret" image and logs every request, so you can watch
// the SSRF land. Bound to 127.0.0.1 only.
//
//   node internal-server.mjs         # listens on 127.0.0.1:8079
//   PORT=9000 node internal-server.mjs
import http from 'node:http'
import zlib from 'node:zlib'

const PORT = Number(process.env.PORT || 8079)

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

const COLORS = { red: [220, 20, 20], blue: [20, 20, 220] }

const server = http.createServer((req, res) => {
  const path = req.url || '/'
  const color = path.includes('blue') ? 'blue' : 'red'
  console.log(`[INTERNAL 127.0.0.1:${PORT}] >>> reached from the Next server: ${JSON.stringify(path)} (returning ${color} "secret")`)
  res.setHeader('content-type', 'image/png')
  res.end(solidPng(200, 200, COLORS[color]))
})
server.listen(PORT, '127.0.0.1', () => {
  console.log(`internal-only service listening on http://127.0.0.1:${PORT}`)
  console.log('waiting for the Next server to fetch it (that is the SSRF)…\n')
})
