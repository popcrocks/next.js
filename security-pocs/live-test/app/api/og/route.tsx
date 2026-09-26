import { ImageResponse } from 'next/og'

// A typical dynamic Open Graph image route. It renders a request-supplied image
// URL into the card — the mainstream `?img=`/`?avatar=` pattern. This is the
// ONLY app-side precondition for the SSRF; everything else is the framework's
// (incomplete) SSRF guard inside next/og.
//
// Try edge too: `export const runtime = 'edge'` — the guard is the same.
export const runtime = 'nodejs'

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const img = searchParams.get('img') ?? 'https://placehold.co/200x200/png'
  const title = searchParams.get('title') ?? 'OG card'

  return new ImageResponse(
    (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          width: '100%',
          height: '100%',
          background: '#fff',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={img} width={200} height={200} alt="" />
        <div style={{ fontSize: 24 }}>{title}</div>
      </div>
    ),
    { width: 400, height: 300 }
  )
}
