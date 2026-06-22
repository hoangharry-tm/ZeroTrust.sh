export default function Architecture() {
  return (
    <section id="architecture" class="py-20 px-4 max-w-6xl mx-auto">
      <h2 class="text-3xl font-semibold text-center mb-6">How it works</h2>
      <p class="text-[#8b949e] text-center max-w-2xl mx-auto mb-10">
        ZeroTrust.sh runs two independent detection paths in parallel.
        Neither path gates the other — a finding confirmed by both receives a cross-path confidence boost.
      </p>
      <div class="rounded-lg overflow-hidden border border-[#30363d] bg-[#161b22]">
        <iframe
          src="../docs/architecture/general-solution-3.html"
          width="100%"
          height="600"
          style="border: none; border-radius: 0.5rem; display: block;"
          title="ZeroTrust.sh Architecture Diagram"
        />
      </div>
      <p class="text-[#8b949e] text-sm text-center mt-4">
        Interactive — scroll to zoom, drag to pan, hover nodes for details.
      </p>
    </section>
  )
}
