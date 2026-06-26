const threats = [
  {
    name: 'Phantom dependencies',
    statNumber: '205,474',
    statLabel: 'phantom packages across 16 LLMs',
    description: "Your manifest imports `requests-auth-aws` — a package that doesn't exist. An attacker registers it with a payload. No CVE list will catch it yet.",
    source: "Spracklen et al., USENIX Security 2025",
    url: "https://arxiv.org/abs/2406.10279",
  },
  {
    name: 'Broken authentication logic',
    statNumber: '36–40%',
    statLabel: 'of AI-assisted code contains CWE vulns',
    description: 'Auth functions that always return success. Missing access-control checks on sensitive endpoints. Logic flaws that pass unit tests but fail under real input.',
    source: "Ferrara et al., arXiv 2024",
    url: "https://arxiv.org/abs/2408.07106",
  },
  {
    name: 'Security regression',
    statNumber: '2.74×',
    statLabel: 'more vulns than human-written code',
    description: 'An auth check is present in commit N, silently absent in commit N+1. Functional tests still pass. No diff alert fires. The Differential Indexer catches the AST-node delta.',
    source: "Veracode 2025 GenAI Report",
    url: "https://www.veracode.com/blog/security-news/veracode-2025-generative-ai-report",
  },
  {
    name: 'Injection & taint flaws',
    statNumber: '85%+',
    statLabel: 'exploitation rate for unpatched injection',
    description: 'SQL injection, SSRF, command injection, and XSS buried in indirect call chains that pattern-only scanners miss. ZeroTrust.sh traces taint through call graphs.',
    source: "Yang et al., arXiv 2026",
    url: "https://arxiv.org/abs/2601.17548",
  },
]

function renderText(text: string) {
  const parts = text.split(/(`[^`]+`)/g)
  return parts.map((part) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      const code = part.slice(1, -1)
      return <code class="text-[10px] bg-white/[0.06] px-[3px] py-[0.5px] rounded border border-white/[0.06] font-mono text-[#e6edf3]">{code}</code>
    }
    return part
  })
}

function SourceTip({ source, url }: { source: string; url?: string }) {
  return (
    <span class="relative inline-flex items-center group/tip">
      <a href={url} target="_blank" rel="noopener noreferrer" class="text-[#58a6ff]/50 cursor-pointer text-sm ml-1.5 select-none no-underline group-hover/tip:text-[#58a6ff] transition-colors duration-150" onClick={(e) => e.stopPropagation()}>†</a>
      <div role="tooltip" class="absolute bottom-full left-1/2 -translate-x-1/2 mb-2.5 px-3 py-3 rounded-xl bg-[#161b22]/70 backdrop-blur-xl border border-white/[0.08] shadow-2xl shadow-black/50 opacity-0 group-hover/tip:opacity-100 transition-all duration-200 scale-90 group-hover/tip:scale-100 pointer-events-none z-50 text-nowrap">
        <div class="flex items-center gap-2.5">
          <div class="w-0.5 h-9 rounded-full bg-linear-to-b from-[#58a6ff] to-[#8b5cf6]" />
          <div class="flex flex-col gap-[1px]">
            <span class="text-[13px] text-[#e6edf3] font-mono leading-tight">{source}</span>
            <span class="text-[11px] text-[#58a6ff]/50 font-mono">click on † to open source →</span>
          </div>
        </div>
      </div>
    </span>
  )
}

function Card({ threat }: { threat: typeof threats[0] }) {
  return (
    <div class="bg-white/[0.03] border border-white/[0.06] rounded-xl p-[1px] transition-all duration-300 hover:bg-white/[0.05] hover:border-[#C2410C]/30 hover:shadow-[0_0_25px_rgba(194,65,12,0.12)] group/card">
      <div class="bg-[#0d1117] rounded-[calc(0.75rem-1px)] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)] h-full flex flex-col">
        <h3 class="font-mono font-medium text-[#e6edf3] text-sm mb-2.5">{threat.name}</h3>
        <p class="text-[#8b949e] text-xs leading-relaxed mb-3">{renderText(threat.description)}</p>
        <div class="mt-auto pt-3 border-t border-white/[0.04] flex items-baseline gap-1.5 flex-wrap">
          <span class="font-mono text-2xl font-bold tabular-nums bg-linear-to-r from-[#58a6ff] via-[#818cf8] to-[#8b5cf6] bg-clip-text text-transparent animate-gradient-shift group-hover/card:brightness-125 transition-all duration-500">{threat.statNumber}</span>
          <span class="font-mono text-[13px] text-[#8b949e]">{threat.statLabel}</span>
          <SourceTip source={threat.source} url={threat.url} />
        </div>
      </div>
    </div>
  )
}

export default function Problem() {
  return (
    <section id="problem" class="py-24 px-4 max-w-6xl mx-auto">
      <h2 class="text-3xl font-semibold text-center mb-4">Vulnerabilities appearing at scale</h2>
      <p class="text-[#8b949e] text-center text-sm max-w-xl mx-auto mb-12">
        Traditional SAST misses these. ZeroTrust.sh was built for them.
      </p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        {threats.map((threat) => (
          <Card threat={threat} />
        ))}
      </div>
    </section>
  )
}
