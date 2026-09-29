// Verbatim guard functions extracted from packages/next/src/compiled/@vercel/og/index.node.js
// (the SHIPPED next/og SSRF guard). Unmodified logic.

var Wu = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
function Yu(A) {
  let e = A.match(/^(?:::ffff:|64:ff9b::|::)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (e)
    return e[1];
  let t = A.match(/^(?:::ffff:|64:ff9b::|::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (t) {
    let r = Number.parseInt(t[1], 16), n = Number.parseInt(t[2], 16);
    return `${r >> 8 & 255}.${r & 255}.${n >> 8 & 255}.${n & 255}`;
  }
  return null;
}
function Ns(A) {
  let e = A.split(".").map((i) => Number.parseInt(i, 10));
  if (e.length !== 4 || e.some((i) => !Number.isInteger(i) || i < 0 || i > 255))
    return true;
  let [t, r, n] = e;
  return t === 0 || t === 10 || t === 100 && r >= 64 && r <= 127 || t === 127 || t === 169 && r === 254 || t === 172 && r >= 16 && r <= 31 || t === 192 && r === 0 && n === 0 || t === 192 && r === 168 || t === 198 && (r === 18 || r === 19) || t >= 224;
}
function qu(A) {
  let e = Yu(A);
  return e ? Ns(e) : !!(A === "::" || A === "::1" || A.startsWith("fc") || A.startsWith("fd") || /^fe[89ab]/.test(A) || /^fe[c-f]/.test(A) || A.startsWith("ff") || /^2001:0?db8(?::|$)/.test(A));
}
function Xu(A) {
  let e;
  try {
    e = new URL(A);
  } catch {
    return true;
  }
  if (e.protocol !== "http:" && e.protocol !== "https:")
    return true;
  let t = e.hostname.toLowerCase();
  return t.startsWith("[") && t.endsWith("]") && (t = t.slice(1, -1)), t === "localhost" || t.endsWith(".localhost") || t.endsWith(".local") ? true : Wu.test(t) ? Ns(t) : t.includes(":") ? qu(t) : false;
}
function Ms(A) {
  if (Xu(A))
    throw new Error(`Image source resolves to a blocked address (SSRF protection): ${A}`);
}

export { Ms as ssrfGuard, Xu as isBlocked };
