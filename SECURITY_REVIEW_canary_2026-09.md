# Security review — Next.js `canary`, changes since 2026‑09‑12

**Repo:** `popcrocks/next.js` (fork of `vercel/next.js`)
**Range reviewed:** `d5276f04` (baseline, 2026‑09‑11) → `ff6ac752` = `v16.4.0-canary.48` (2026‑09‑25)
**Scope:** 252 commits. The focus was vulnerabilities *introduced* in this window, and security fixes in the window that are *incomplete / bypassable*. Pre‑existing issues are noted only when a window commit makes them newly reachable or is an incomplete attempt to fix them.

**Method:** commit triage → 8 parallel focused reviews (server routing, caching/PPR/root‑params, build tracing/distDir, CLI/agent tooling, compiler transforms, dev‑server/overlay, next/og + React, CI/CD) → independent verification of each reported finding against the code at HEAD. There is no built Next.js in this checkout, so runtime‑level claims were verified by tracing the code and with isolated Node/React harnesses, **not** end‑to‑end against a running app. Confidence levels below reflect that.

> ⚠️ These are engineering findings from a code review, not confirmed CVEs. They deserve a maintainer's confirmation (ideally a runtime repro) before they're treated as real. None is a wormable, unauthenticated RCE.

> 📌 **A second, higher-severity pass was run afterward** (broadened beyond the 2‑week diff to the *current state* of the classic High/Critical surfaces, with a patch-bypass focus). It found **3 High-severity issues** and re-graded two Round‑1 items. See **[Round 2 — High-severity pass](#round-2--high-severity-pass)** at the bottom; the Round‑1 table below is unchanged from the first pass.

---

## Summary table

| # | Severity | Confidence | Finding | Introducing commit | Preconditions |
|---|----------|-----------|---------|--------------------|---------------|
| 1 | Medium | High | `dynamicParams = false` admission bypassed by a form‑encoded `POST` | `851b6cb0` (incomplete fix / pre‑existing) | `next start` or non‑minimal adapter; a closed dynamic route |
| 2 | Medium | Medium | Nested `'use cache'` cross‑tenant disclosure via late root‑param propagation | `d0df62e8` (incomplete fix) | `cacheComponents`; `next/root-params` read in a nested cache that returns an unconsumed pending value |
| 3 | Medium | Medium | Shared prerender shell poisoned via literal `[param]` placeholders in the URL | `6866b944` | `cacheComponents`; specific multi‑param route shape; self‑hosted |
| 4 | Medium | High (mechanism) | `next upgrade --ai` treats any open PR as trusted: stops security upgrades + feeds attacker text to a privileged agent | `5d9ab72c` | Maintainer uses `next upgrade --ai` / agentic auto‑upgrade; public repo |
| 5 | Low | High | Dev HMR broadcasts per‑document token → LAN attacker hijacks React debug channel (+ DoS, forged errors) | `4d925698` | Dev only; **opt‑in flag off by default**; dev server reachable on network |
| 6 | Low | High | `distDir` safety check bypassable by case/symlink → `next build` deletes app source | `8fab0b4b` (incomplete fix) | Misconfigured `distDir` (no external attacker) |
| 7 | Low | Medium | `turbopackAdditionalRoots` code traces unrelated project files (secrets) into deploy output | `7b58e588` | Experimental flag; `__dirname`+`fs` in a linked package |
| 8 | Low | Medium | Windows command injection in the AI‑upgrade launcher when app path contains `&` | `5d9ab72c` | Windows; `.cmd` shim; `&` in path |
| 9 | Low | High | Agent‑feedback telemetry opt‑out ignores `.env` `NEXT_TELEMETRY_DISABLED` | `a2470dbd` (incomplete fix) | Consent gap; no external attacker |
| 10 | Low | Med‑High | `dynamicParams=false` catch‑all bypass via line terminators (`%0A`, `%E2%80%A8`…) | pre‑existing; `851b6cb0` gate doesn't close it | `[...slug]`/`[[...slug]]` closed route |

Clean areas (no qualifying issues): **compiler transforms**, **next/og hardening + the three React upgrades** (Flight‑reply decoder was *hardened*, not weakened — see below), **CI/CD workflows** (several changes are net hardening).

---

## Medium findings

### 1. `dynamicParams = false` admission bypassed by a form‑encoded POST
**`851b6cb0` · High confidence · `packages/next/src/build/templates/app-page-runtime.ts:1737`, `server/app-render/action-handler.ts:682`, `server/lib/server-action-request-meta.ts:28`**

`851b6cb0` moved closed‑route admission into an early gate that rejects unlisted params "regardless of cache state" — but the gate is skipped when `isPossibleServerAction` is true:

```ts
if (!isMinimalMode && !isDraftMode && !isPossibleServerAction &&
    pageIsDynamic && prerenderInfo?.fallback === false && !isPrerendered) {
  throw new NoFallbackError()      // 404 for unlisted params
}
```

`isPossibleServerAction` is true for **any** `POST` with `Content-Type: application/x-www-form-urlencoded` or `multipart/form-data` — no `Next-Action` header required. Such a request is deliberately flowed through to `handleAction`, which returns `null` for a URL‑encoded non‑fetch POST (`action-handler.ts:682-689`). Back in `app-render.tsx:3164`, `if (actionRequestResult)` is skipped on `null`, so **execution falls through to normal page rendering**.

**Impact:** for a route with `dynamicParams = false` (or `generateStaticParams` acting as an allowlist):
- `GET /products/draft-123` → `404`
- `POST /products/draft-123` with `Content-Type: application/x-www-form-urlencoded` → `200`, full server render for `slug='draft-123'`.

Any app that relies on `dynamicParams = false` as an access boundary (CMS drafts addressed by slug, IDs used to build file paths — a single segment can carry `/` via `%2F`) serves content it intended to gate. This is the **broadest** finding: it needs no experimental flag, only a stable, common feature. It may be pre‑existing (the pre‑`851b6cb0` check was also skipped for actions), so `851b6cb0` is best read as an incomplete fix.

**Fix:** if `handleAction` returns `null` (not actually an action), apply the closed‑route 404; never render a page tree for a non‑admitted URL.

### 2. Nested `'use cache'` cross‑tenant disclosure via late root‑param propagation
**`d0df62e8` (incomplete fix) · Medium confidence · `server/request/root-params.ts:71`, `server/use-cache/use-cache-wrapper.ts:664` & `:1224`**

A root‑param read (`next/root-params`) is recorded only on the *innermost* cache store (`root-params.ts:71`; `getRootParam` does not walk up). It reaches an enclosing cache only through the inner's `collectResult`, which **drains the inner RSC stream to completion before propagating** the read upward. `saveToCacheHandler` stores the real entry at the *coarse* (root‑param‑independent) key whenever the set is empty at save time:

```ts
const rootParamNames = readRootParamNames ? addKnownRootParamNames(id, readRootParamNames) : ...
if (rootParamNames && rootParamNames.size > 0 && rootParams) { /* specific key + redirect */ }
cacheHandler.set(cacheHandlerKeyBase, Promise.resolve(coarseEntry))   // coarseEntry === fullEntry when set is empty
```

If an inner cache returns a value with an **un‑consumed pending part** (an un‑awaited promise / lazy element / async iterable) while the outer awaits only the settled fields, the outer's stream closes and it saves *before* the inner's stream drains and propagates the root‑param dependency. The outer entry then lands at the coarse key with no `_N_RP_` redirect and no root‑param tag — so tenant A's rendered content is served to tenant B (or an attacker who owns a tenant can poison it), including into on‑demand ISR fallback shells. Because the tenant tag is also dropped, `revalidateTag` won't evict it.

`d0df62e8` fixed the sibling case where propagation waited for handler *writes* to settle; its regression tests hold a *write* pending, not a *collection* (pending‑value) delay, so this variant remains. The finding rests on the React Flight timing (inner stream stays open on an unconsumed promise while the outer closes early) — verified with the vendored `react-server-dom` builds by the reviewer, but not end‑to‑end in Next.

**Fix:** make the outer's metadata complete before it's used — register nested/joined `pendingMetadata` on the enclosing store and await it in `collectResult` before building the entry, or propagate root‑param reads eagerly up the store chain in `getRootParam`.

### 3. Shared prerender shell poisoned via literal `[param]` placeholders
**`6866b944` · Medium confidence · `build/templates/app-page-runtime.ts:627` & `:1509`, `server/request/fallback-params.ts:104`**

`getPlaceholderFallbackRouteParams` defers only the params whose **request value equals the placeholder string** (`item === '[item]'`). In production the code honors request‑supplied placeholders with no check that they came from the platform (`!routeModule.isDev && pageIsDynamic && prerenderInfo?.fallbackRouteParams`). `6866b944` broadened the shared shell key from `partialPrefetching`‑only to *any* `cacheComponents` app with remaining fallback params.

For a route like `app/[lang]/shop/[category]/[item]` (only `lang` has `generateStaticParams`; a `[category]` layout reads `params.category`), an attacker requests `GET /de/shop/EVIL/%5Bitem%5D`. Only `item` is deferred; `category='EVIL'` renders concretely and is written under the shared key `/de/shop/[category]/[item]`. Every later visitor to `/de/shop/*/*` gets the attacker's `EVIL` prelude (content spoofing, or a cached `404`/DoS if the layout calls `notFound()` for unknown categories). Persists until revalidation; the attacker re‑poisons after each staleness window.

Verified: placeholder‑param selection, request‑placeholder honoring in prod, and the shared‑key broadening. Not verified end‑to‑end: the exact persistence of the concrete value into the served shared entry (`hasOmittedConcreteFallbackParam` / `buildCompletedShellCacheKey` write path).

**Fix:** on any shared‑shell‑key write, defer `union(placeholderParams, remainingFallbackRouteParams)` — never a smaller set; or honor placeholder values only from the platform (minimal mode / `renderFallbackShell`).

### 4. `next upgrade --ai` trusts any open PR
**`5d9ab72c` (carried into `shared.mdx` by `f2c2f781`) · High confidence on mechanism · `docs/01-app/02-guides/upgrading/agentic-upgrade/shared.mdx`, wired at `cli/next-upgrade.ts:452`**

The agentic‑upgrade prompt (shipped as `next/dist/docs/.../shared.md`) instructs the launched AI agent to run `gh pr list --state open --limit 100 --json number,title,body,url,headRefName` and `gh pr diff <number>`, and to **stop before changing files** if it finds "existing work" marked with `<!-- next-upgrade: <type>; path="." -->`. There is no filter by author, fork status, or write permission.

**Impact:** anyone who can open a PR on a public repo can (a) permanently **stop the automated security upgrade** by opening a fork PR carrying the marker — the app stays on the vulnerable version (the `security-duplicate` eval encodes exactly this stop); (b) get their PR presented to the maintainer as "the upgrade"; and (c) inject their PR **body and diff into the context of an agent** that then runs installs, codemods, `git` and `gh` with the maintainer's permissions. Reachable autonomously via the `experimental.agenticAutoUpgrade` nudge that fires during `next dev`/`next build`.

**Fix:** only count same‑repo PRs from trusted authors as duplicates (add `isCrossRepository,author`, require `isCrossRepository == false`); have the CLI do a filtered API lookup and hand the agent structured data rather than raw bodies/diffs; report a candidate and ask rather than hard‑stopping; tell the agent PR content is untrusted.

---

## Low findings

**5. Dev HMR runtime‑error broadcast (`4d925698`, opt‑in flag off by default).** With `experimental.exposeRuntimeErrorsToHMR` (default `false`), each tab's per‑document token `htmlRequestId` is broadcast to *all* HMR sockets. A LAN attacker (or a malicious site, given the default `0.0.0.0` bind and origin checks that allow no‑Origin connections) can reconnect with `?id=<token>`, overwrite the victim's entry in `clientsByHtmlRequestId` (no auth/overwrite check), and receive the victim's React debug channel — server‑component props, console replays, awaited I/O values (`hot-reloader-turbopack.ts:1568,1790,1841`). Also: runtime‑error snapshots have no size/count limit and are stored + replayed (memory DoS), and forged errors can be pushed to observing agents (prompt injection). Dev‑only and off by default, hence Low; the underlying `?id` hijack is a pre‑existing App‑Router‑HMR property. **Fix:** don't broadcast `htmlRequestId`; refuse an `?id` already bound to an open socket; cap payload/size.

**6. `distDir` safety check bypass → deletes app source (`8fab0b4b`, incomplete fix).** `lib/dist-dir.ts` compares path strings only (its own `TODO` admits symlinks aren't handled). On case‑insensitive filesystems `distDir: '../Web'` / `'../../Apps'` pass; a `distDir` that is a symlink to the app or workspace root passes (reproduced on Linux). `next build` then recursively deletes `app/`, `pages/`, `src/`, `public/`, `.git/`. Also the reserved‑name check matches only the literal `'public'`, so `'./public'`/`'public/'` slip through. Misconfiguration‑only (no external attacker), but it's exactly the data loss the commit meant to prevent. **Fix:** compare realpath + device/inode before every recursive delete.

**7. `turbopackAdditionalRoots` traces unrelated project files (`7b58e588`, experimental).** Code in an additional root that lives *outside* `node_modules` (e.g. an `npm link`ed package) has its `__dirname`‑based `fs` patterns resolved against the **project root** (`references/mod.rs:917,2066,4303`). A `fs.readFileSync(path.join(__dirname, name))` becomes `/ROOT/<dynamic>` and traces across the whole project, pulling unrelated files (`certs/*.key`, `service-account.json`) into `.nft.json` → `.next/standalone`/adapter output, while the package's own files go missing. Accidental exposure (no attacker gain), gated on an experimental flag. **Fix:** resolve `/ROOT/` patterns against the module's own filesystem root.

**8. Windows command injection in the AI‑upgrade launcher (`5d9ab72c`).** `harness.ts` passes `JSON.stringify`‑quoted paths as the prompt argument to a global `claude.cmd`/`codex.cmd`. `cross-spawn` only double‑escapes shims under `node_modules/.bin`; a global npm shim gets a single `^` layer, and cmd re‑parses `"%_prog%" "cli.js" %*`, so a `&` in the app path (e.g. `OneDrive - AT&T`, `C:\src\R&D\web`) starts a new command. Needs Windows + a `.cmd` shim (not a native `.exe`) + `&` in the path (rarely attacker‑controlled). **Fix:** strip `"` from the prompt on the win32 `.cmd` branch, or launch `node <cli.js>` directly.

**9. Agent‑feedback telemetry opt‑out gap (`a2470dbd`, incomplete fix).** `cli/internal/agent-feedback-instructions.ts:48` checks `isCI` and `Telemetry(.next).isEnabled` but never calls `loadEnvConfig`, so `NEXT_TELEMETRY_DISABLED=1` set in `.env`/`.env.local` is **not** honored by the internal command (though `next dev` honors it), and it hardcodes `.next` (misses a custom `distDir`). A consent gap only — no external attacker, nothing auto‑submitted. **Fix:** `loadEnvConfig` + resolve `distDir`/`agentFeedback` before the gate request.

**10. `dynamicParams=false` catch‑all bypass via line terminators (pre‑existing; `851b6cb0` gate doesn't close it).** For `[...slug]`/`[[...slug]]`, the prerender matcher compiles catch‑all segments to `'/(.+?)'`, and `.` doesn't match `\n`, `\r`, U+2028, U+2029. `GET /docs/secret/%0A` misses the matcher → `prerenderInfo` is `null` → the admission gate is skipped → dynamic `200` render of an unlisted path. Single‑segment `[slug]` is unaffected (`[^/]` matches newlines). **Fix:** derive closedness from the route's own manifest entry when no specific entry matches, or compile the matcher with the `s` flag.

---

## Notable leads (unconfirmed — worth a look)

- **`/index` → `/` home‑page poisoning** (pre‑existing, likely real). `route-module.ts:1073` rewrites `resolvedPathname === '/index'` to `/`; for a root‑level `app/[slug]`, `GET /index` can regenerate and overwrite the home page's ISR entry with `slug='index'`.
- **`next-routing/src/destination.ts`** inserts `has` captures (from header/cookie/query values) into rewrite/redirect destination paths **without encoding** (pre‑existing; `bfcf687f` only made substitution single‑pass). Worth a dedicated path/query‑injection review for adapter deployments.
- **Symlinked‑directory trace loop** (`7b58e588`): `turbopack-core/src/resolve/pattern.rs:1880` recurses into symlinked directories with no ancestor/loop guard (unlike `read_glob`), so a `loop -> ..` symlink under a traced directory can hang the build / OOM.
- **`draftMode()` leading a public `'use cache'` fill** (pre‑existing): no `isDraftMode` gate on the cross‑request join, so concurrent public requests (including ISR prerenders) could receive draft content.
- **HTML‑bot User‑Agent ReDoS** (`html-bots.ts`, pre‑existing): the `[\w-]+-Google` prefix is quadratic (~260 ms for a 16 KB UA), evaluated several times per request; `b67a1182` adds one more evaluation in Edge SSR.

---

## What was clean

- **React upgrades (`65e29e4a`, `0927d3e8`, `1a723afd`).** The Flight‑reply decoder — the historically dangerous Server‑Action argument deserialization path (CVE‑2025‑55182 class) — was **hardened**: per‑response `WeakMap` for server references (removing an attacker‑controllable `$$promise` field on the reference object), and object server‑references are refused by property‑path traversal and by the Map/Set/Iterator initializers. All prior guards (`"then"` rejection, `__proto__` guards, own‑property/plain‑prototype checks, bound‑arg/array/BigInt limits) remain. Fizz/Flight HTML escaping and `javascript:` sanitization are unchanged. Verified with decoder harnesses.
- **`next/og` SVG hardening (`51603630`).** A real satori markup‑injection class was fixed completely — all markup now flows through one builder with XML‑name validation + `escape-html`; both compiled bundles reproduce the patch byte‑for‑byte. Pre‑patch exploitability was limited anyway (ImageResponse returns PNG only; resvg has no fs/network access).
- **Compiler transforms.** No server→client leakage and no callable‑without‑registration action. The `'use server'`/`'use client'` directive‑integrity area fails **closed** before and after `bdbf63ae`; tree‑shaking changes can only remove code, with Flight‑visible names preserved.
- **CI/CD.** The PR‑stack‑gate rewrite is read‑only and fail‑open (removed a third‑party action + an inherited secret); `trigger_release.yml` was hardened against workflow‑input injection; the preview‑tarball artifact path is protected against zip‑slip.

---

*Reviewed by Claude Code. Findings are code‑level and (except where noted) not reproduced against a running Next.js; confirm the Mediums with a runtime repro before acting.*

---

## Round 2 — High-severity pass

After the first pass topped out at Medium, a second wave (five focused hunters) went after the classic High/Critical Next.js surfaces at the **current HEAD** (not just the 2‑week diff), with a dual mandate: confirm each major historical fix is still complete (**patch-bypass** analysis — no code was modified), and find new flaws. Every finding below was re-verified against the code by the lead; `next/og`, the Flight decoder, and the middleware fix were also checked with executed harnesses by the reviewers.

### Confirmed still-solid (patch-completeness passes — good news)
- **CVE‑2025‑29927 (`x-middleware-subrequest` middleware auth bypass): fully closed.** The header and all its readers are gone from `packages/next/src` (verified: zero matches); middleware is now gated by unforgeable internal request‑meta (`middlewareInvoke`), not a header. No residual bypass. The `x-invoke-path/query/output/status` family is likewise gone.
- **Flight‑reply deserialization RCE (CVE‑2025‑55182 "React2Shell") class: not reachable via Next's usage.** Next's server‑module‑map proxy (`manifests-singleton.ts:344`) **throws** for an unknown or composite `id#export` (rather than returning `undefined`), which makes React's `#`‑based export‑override fallback unreachable — a genuine near‑miss (returning `undefined` there would have been arbitrary‑export RCE). Confirmed by executing the real vendored production decoder against a battery of malicious IDs — none invoked an unintended function. Bound‑arg encryption (AES‑GCM‑256, per‑build CSPRNG key, action‑ID‑bound plaintext) and the Server‑Action CSRF Origin/Host check are sound.
- **Request‑time path traversal (`/_next/static`, `/_next/data`, public): contained** by three independent layers (URL dot‑segment collapse → exact set‑membership in prod → vendored `send`'s `..` rejection), harness‑proven; core files unchanged since baseline.
- **Image allowlist matcher + `isPrivateIp` guard: no deterministic bypass** (harness‑proven against the real picomatch/ipaddr.js the repo pins — `@`/IDN/octal/wildcard host tricks all rejected).

### New High-severity findings

**H1 — Image optimizer DNS‑rebinding SSRF (`/_next/image`).** *High, config‑gated · High confidence on code path.*
`packages/next/src/server/image-optimizer.ts:521-553`. `fetchExternalImage` resolves the hostname (`lookup`, `:531`), checks every resolved IP against `isPrivateIp` (`:538`), then calls `fetch(href, …)` (`:550`) with the **hostname** — no pinned‑IP undici dispatcher. undici re‑resolves DNS at connect time, so the vetted IP and the connected‑to IP are two independent lookups → classic TOCTOU. An attacker who controls a rebinding DNS name (public IP on the first lookup, `169.254.169.254`/`127.0.0.1` on the connect) reaches internal network resources from the server.
- **Precondition:** the app's `images.remotePatterns` must match an attacker‑chosen hostname — canonically `{ protocol:'https', hostname:'**' }`, a documented, commonly copy‑pasted config for apps that display user‑supplied remote images. Narrow allowlists (`images.example.com`, `*.cdn.com`) are **not** exploitable (the attacker can't make those names resolve to their rebinder). Built‑in optimizer only (self‑hosted `next dev`/`next start`); replaced on managed hosts like Vercel.
- **Impact:** internal endpoints that return image bytes are fully read; the upstream HTTP status is reflected (`:589`) → internal port/existence oracle. Non‑image bodies are rejected (metadata JSON stays blind) and no auth headers are sent, so it's an internal‑network SSRF, not a trivially full metadata read — still High.
- **Fix:** resolve once, then connect to the vetted IP (custom `undici` `Agent` whose `connect.lookup` returns only that IP, or connect‑by‑IP with a `Host` header); re‑vet on every redirect hop. Pre‑existing at HEAD, not a window regression.

**H2 — Unauthenticated home‑page cache poisoning via `/index` → `/` collision.** *High · Medium‑High confidence (code chain verified; two runtime‑dependent steps unconfirmed without a running server).*
`packages/next/src/server/route-modules/route-module.ts:1073-1075` collapses `resolvedPathname === '/index'` to `'/'` **unconditionally** — including right after interpolating a dynamic route. So a root‑level dynamic route `app/[slug]/page.tsx` rendered for `slug='index'` takes the **home page's** ISR/SSG cache key `/` (both normalize to the same store entry `app/index.html`/`.rsc` via `normalizePagePath`). On a self‑hosted `next start`, an unauthenticated `GET /index` routes to `/[slug]` (there's no earlier `/index`→`/` normalization on that path), and when the home entry is stale or missing, the regeneration writes the `[slug]`‑for‑`index` render onto `/`, persistently (survives restart; also poisons the `.rsc` consumed by client navigations).
- **Precondition:** self‑hosted prod; a root‑level dynamic segment (`/[slug]`/`/[...x]`); a home page that is prerendered **and** can go stale (ISR `revalidate` / tag eviction); `[slug]` produces a cacheable response for `slug='index'`. Deployment/minimal mode normalizes `/index` earlier, so this is primarily the self‑hosted runtime.
- **Impact:** persistent defacement/DoS of the site's most visible page with no auth and a trivial trigger (`GET /index` during the staleness window). Content is deterministic (`[slug]`'s render), so integrity/availability rather than arbitrary injection.
- **Unverified without runtime:** that `GET /index` actually routes to `[slug]` (vs. the home route), and that `[slug]` returns a cacheable 200 for `index` — both app‑shape‑dependent.
- **Fix:** only collapse `/index`→`/` for the literal home route (`normalizedSrcPage === '/'`), not for an interpolated dynamic route; or include the matched route identity in the response‑cache key. (Round‑1 lead L1, now confirmed.)

**H3 — `dynamicParams = false` admission bypass via form‑encoded POST (re‑graded from Round‑1 #1, + DoS amplification).** *High · High confidence.*
This is Round‑1 finding #1, escalated. Verified again at HEAD: a `POST` with `Content-Type: application/x-www-form-urlencoded` (no `Next-Action` header) sets `isPossibleServerAction`, which (a) skips the closed‑route admission gate (`app-page-runtime.ts:1737`) so a non‑allowlisted param renders `200` instead of `404`, and (b) forces `ssgCacheKey = null` (`app-page-runtime.ts:657`) so the render is never cache‑read or cache‑written.
- **New impact 1 — RSC data exfil:** the same POST with `RSC: 1` returns the Flight payload for the non‑allowlisted param (not just HTML), so `generateStaticParams`/`dynamicParams=false` used as an access boundary (CMS drafts by slug, unpublished IDs) is bypassed for data too. (`notFound()`‑based gating is *not* bypassed — the page's own `notFound()` still runs.)
- **New impact 2 — cache‑bypass DoS amplification:** because `ssgCacheKey` is null for *every* form‑content‑type POST, a `POST` to **any** SSG/ISR page defeats the Full Route Cache and forces a full uncached render per request — cheap cached responses (and cheap 404s) become expensive renders on demand.
- **Attack:** `curl -X POST -H 'content-type: application/x-www-form-urlencoded' https://site/products/<unlisted>` → `200` with the gated render; no auth/CSRF token needed. Self‑hosted prod (and adapters exempt actions similarly).
- **Fix:** if `handleAction` returns `null` (not a genuine action), re‑apply the closed‑route 404 before rendering; and narrow the gate exemption to requests carrying a valid decoded action rather than any form‑content‑type POST.

### New Medium / Low findings
- **M‑a — Image optimizer follows redirects without re‑validating `remotePatterns`** (`image-optimizer.ts:567-586`). The redirect recursion re‑runs the `isPrivateIp` guard (private IPs still blocked) but never re‑checks the allowlist, so an allowed host that emits a redirect turns the optimizer into an **open proxy to any public host** (origin masking; defeats third‑party egress‑IP allowlists). *Medium.* Fix: re‑run `hasRemoteMatch` on every hop.
- **M‑b — Adapter NFT copy lacks the containment guard the standalone path enforces** (`build/adapter/build-complete.ts` `loadNFT` vs `build/utils.ts` `handleTraceFiles`; `nft.ts:146,167`). Standalone routes every write/symlink destination through `resolveNftOutputPath` (throws on escape); the deployment‑adapter path does not, and `mapAdditionalRootPath` builds a destination from an unvalidated `root.name`. An escaping `.nft.json` entry or a crafted `additionalRoots[].name` could write outside the deploy artifact **if** the adapter copies destinations verbatim. *Medium, build‑time* — needs a malicious build dependency or misconfig + an experimental adapter; not remotely triggerable. Fix: call `resolveNftOutputPath` in `loadNFT`; validate `root.name`.
- **L‑a — `x-action-forwarded` is a forgeable internal header** (`action-handler.ts:801`; not in `INTERNAL_HEADERS`, verified). Forging it only affects the attacker's own request (skips their post‑action re‑render, or causes a per‑action error in multi‑worker deployments) — the CSRF check runs first. *Low.* Fix: add to `INTERNAL_HEADERS` (or thread as internal meta).
- **L‑b — Dev‑only endpoints** (`next dev` binds `0.0.0.0`): `/__nextjs_source-map?filename=` is a constrained file‑read oracle (returns only a trailing `sourceMappingURL`, not file contents), and `/__nextjs_launch-editor?file=` opens an arbitrary existing file in the developer's editor via GET with no Origin check (no shell, so no command injection). *Low, dev‑only, pre‑existing.*
- **L‑c — Draft‑mode content can transiently leak via an un‑gated cross‑request cache join** (`use-cache-wrapper.ts:3097,3225` vs the persistence gate at `:3566`). A draft‑mode request can lead a shared public `'use cache'` fill that a concurrent normal request joins, receiving unpublished content — but only in‑memory/for the in‑flight race window (persistence *is* gated), and draft mode isn't attacker‑enableable in prod (the `__prerender_bypass` token is a per‑build CSPRNG secret). *Low, defense‑in‑depth.* Fix: `skipCrossRequestDedupe ||= isDraftMode`.

### Refuted
- **Rewrite/redirect `destination` injection** (`packages/next-routing/src/destination.ts`): **not applicable to the self‑hosted runtime.** `@next/routing` has zero consumers inside `packages/next/**`; the self‑hosted request path uses the hardened `prepare-destination.ts`, which encodes `has`‑captures (`encode: encodeURIComponent` for the host). The unencoded substitution in `destination.ts` is a latent Low only for an external adapter consumer that ships a dangerous scheme‑prefixed template.

### Round 2 net
Three High‑severity issues, all reachable by an unauthenticated attacker; **H1 and H3 are the most broadly applicable** (H3 needs no experimental flag, only `dynamicParams=false`; H1 needs a broad `remotePatterns`). H2 hits the highly common "root dynamic route + ISR home" shape. The historically critical classes (middleware‑header bypass, Flight RCE, path traversal) are confirmed intact — the severity here comes from admission‑control, cache‑keying, and SSRF logic, not memory‑safety or deserialization.

---

## Round 3 — RCE hunt

Explicit hunt for a remote code execution vulnerability (the highest-value target), five hunters across the surfaces where an RCE could realistically live at HEAD. **No production RCE was found.** The core RCE classes are confirmed closed — several with *executed* proofs against the real vendored decoders — and the new findings are a High DoS and a dev-only conditional-RCE. Reporting the negatives explicitly because they define where the boundary holds.

### Confirmed closed (RCE classes — executed/thorough proofs)
- **RSC/Flight deserialization (all call sites, all runtimes).** Enumerated all 20 Flight decode sites; ran the real webpack **and** turbopack production decoders against crafted attacker payloads. Every site that decodes attacker bytes passes the gated throwing `serverModuleMap` proxy (`manifests-singleton.ts:344`); the only `null`-map sites decode the server's own SSR render and are inert (deferred closure + `noServerCall`). React's `#`-export-override fallback — the RCE primitive — is unreachable in **webpack/turbopack × node/edge** because the proxy throws first. Control cases proved a permissive/`{}` map *would* be RCE; no Next site passes one.
- **Prototype pollution → gadget.** No global `Object.prototype` pollution primitive exists on the server request path (every parser is flat / null-proto / single-level / schema-validated; core does no in-place recursive merge of request data — harness-confirmed). A strong sink exists (`require.ts` `checkManifest` reads `manifest[page]` without an own-property guard) but is unreachable for lack of a primitive and because `page` comes from route resolution, not raw URL text. *(Defensive hardening: `Object.hasOwn(manifest, page)` / null-proto manifests.)*
- **Cache / RDC / incremental-cache deserialization.** Every cache restore is JSON-without-reviver on server-only bytes, or a Flight decode with the gated map. The round-2 cache-poisoning primitives influence render *inputs*, but stored bytes remain well-formed server-generated Flight, so they can't smuggle a crafted reference or `__proto__` key past the guards.
- **`eval`/`Function`/`vm`/dynamic-`require`/`child_process` sinks.** No production request-reachable dynamic-exec sink: requires are manifest-key-gated, the edge sandbox runs build output with `codeGeneration` disabled in prod, dynamic `import()` specifiers are config/build-derived, all build codegen is `JSON.stringify`-interpolated, and there is no `child_process` on any request path.

### New findings (Round 3)
**H4 — Unauthenticated resource-exhaustion DoS via `/_next/image` (pixel/CPU flood).** *High · verified.*
`hasLocalMatch` returns `true` when `images.localPatterns` is unset (**local images are allow-all by default** — `match-local-pattern.ts:19`), `imgOptMaxInputPixels` defaults to 268MP (`config-shared.ts:2398`), `imgOptConcurrency` is `null`, and the only concurrency control is sharp's internal thread count *per operation* — there is **no application-level cap on concurrent optimizations**. A small, highly-compressed image (well under the 50 MB body cap) decodes to ~1 GB of raw pixels in libvips before resize; the 7 s `.timeout()` bounds the CPU loop but not the decode allocation. An unauthenticated attacker varies `q` (1–100) / `href` to defeat cache coalescing and issues many parallel `/_next/image` requests → memory exhaustion (OOM kill) or CPU saturation. Reachable on self-hosted `next start` (non-minimal); needs either a permissive `remotePatterns` or a same-origin endpoint returning attacker bytes (local allow-all). Fix: add a concurrency semaphore/queue and lower the default max input pixels.

**H5‑class surface (not a confirmed vuln) — attacker bytes reach `sharp`/libvips native codecs via `/_next/image`.** *Critical class, but no live CVE at HEAD.* The JPEG/PNG/WebP/AVIF-HEIF/TIFF/GIF decoders (historically the source of critical heap-overflow RCEs, e.g. libwebp CVE‑2023‑4863, libheif) are fed up to 50 MB of attacker-controlled bytes. The pinned `@img/sharp-libvips@1.3.3` (~libvips 8.17) has no known unpatched CVE, so this is a **reachable delivery path** whose exploitability depends entirely on the deployed sharp/libvips version — not a confirmed RCE. Keep sharp/libvips patched; the loader allow-list (blocking PDF/EXR/etc.) is good and SVG is correctly not routed to librsvg. Reported honestly as surface, not a finding.

**M‑c — Dev server: cross-site navigation bypasses `blockCrossSiteDEV`, force-opening the Node inspector (and other side-effectful `/__nextjs_*` endpoints).** *Medium, dev-only, escalates to RCE on shared/cloud dev hosts · verified.*
`block-cross-site-dev.ts` blocks cross-site `no-cors` requests (via Referer) and requests carrying a disallowed `Origin`, but its final branch only blocks when an `Origin` is present — and a cross-site **top-level navigation** (`<iframe src>`, `window.open`, GET form) sends `Sec-Fetch-Mode: navigate` with **no** `Origin`, so it is allowed. `/__nextjs_attach-nodejs-inspector` (mounted unconditionally in dev) then calls `inspector.open(9229)`. A malicious page a developer visits while `next dev` runs force-enables the V8 debugger on their process. A pure web attacker can't connect (the inspector WS UUID isn't cross-origin-readable and the inspector resists DNS-rebinding), but on shared/cloud dev hosts (Codespaces, Gitpod, devcontainers) another party who can reach `:9229` gets **RCE**; the same gap also lets a malicious page trigger `/__nextjs_launch-editor` (open an arbitrary existing file in the dev's editor) and the source-map read endpoints. Fix: block by `sec-fetch-site: cross-site` regardless of mode (cover navigations); don't force-open the inspector from an HTTP endpoint; set `X-Frame-Options`/`frame-ancestors` on `/__nextjs_*`.

**L‑d — `next-codemod` runs `execa(..., { shell: true })` without argument escaping** (`handle-package.ts`), so a package name/version containing shell metacharacters injects. Local CLI only; exploitable if run against an untrusted repo whose `package.json` drives the install. *Low.* Fix: drop `shell: true`.

### Round 3 net
No production RCE at HEAD; the classically RCE-prone paths (Flight deserialization, prototype pollution, cache deserialization, dynamic-exec sinks) are hardened and were proven so. The residual highest-severity items are the `/_next/image` DoS (**High**) and the dev-only inspector force-open (**Medium**, RCE only on shared/cloud dev hosts). The one true RCE *surface* — attacker bytes into `sharp`/libvips — is gated behind keeping the native image library patched.
