export default function Home() {
  return (
    <main style={{ fontFamily: 'sans-serif', padding: 24 }}>
      <h1>og-ssrf-live-test</h1>
      <p>
        The vulnerable route is <code>/api/og?img=&lt;url&gt;</code>. See
        <code> README.md</code> for the SSRF test steps.
      </p>
      <p>
        <a href="/api/og?title=hello&img=https://placehold.co/200x200/png">
          /api/og (benign example)
        </a>
      </p>
    </main>
  )
}
