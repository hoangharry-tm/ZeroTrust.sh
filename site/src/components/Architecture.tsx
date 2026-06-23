import ArchitectureTabs from './ArchitectureTabs'

export default function Architecture() {
  return (
    <section id="architecture" class="py-20 px-4 max-w-6xl mx-auto">
      <h2 class="text-3xl font-semibold text-center mb-6">How it works</h2>
      <p class="text-[#8b949e] text-center max-w-2xl mx-auto mb-10">
        ZeroTrust.sh runs two independent detection paths in parallel.
        Neither path gates the other — a finding confirmed by both receives a cross-path confidence boost.
      </p>
      <div class="rounded-lg border border-[#30363d] bg-[#161b22] p-6">
        <ArchitectureTabs />
      </div>
      <iframe
        src="/ZeroTrust.sh/general-solution-3.html"
        class="w-full min-h-[450px] md:min-h-[550px] mt-10 rounded-lg border-0"
        title="ZeroTrust.sh pipeline diagram"
        loading="lazy"
      />
    </section>
  )
}
