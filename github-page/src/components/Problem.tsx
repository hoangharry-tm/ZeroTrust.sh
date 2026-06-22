const threats = [
  {
    name: 'Package hallucinations',
    description: "An agent imports `requests-auth-aws` (non-existent). An attacker registers it with a payload. Your scanner sees nothing — the package isn't on any CVE list yet.",
    wide: false,
  },
  {
    name: 'Prompt injection in source',
    description: 'Adversarial instructions in comments, docstrings, or string literals that redirect the next agent that reads this file.',
    wide: false,
  },
  {
    name: 'Security-node disappearance',
    description: 'An auth check is present in commit N, silently absent in commit N+1. Functional tests still pass. No diff alert fires.',
  },
  {
    name: 'Instruction file backdoors',
    description: 'Unicode obfuscation (U+202E, U+200B) buried in `CLAUDE.md`, `.cursor/rules`, `AGENTS.md`, or MCP configs. No competitor scans this surface.',
    wide: false,
  },
  {
    name: 'Agent cheat patterns',
    description: '`return True` in `*auth*` functions. `TODO: add auth` with no follow-through. Disabled assertions that make the test suite green.',
    wide: false,
  },
  {
    name: 'MCP server config injection',
    description: 'External URLs, shell/execute capabilities, and over-broad filesystem scopes injected into `.mcp.json`.',
  },
]

function Card({ threat }: { threat: typeof threats[0] }) {
  return (
    <div class="bg-white/[0.03] border border-white/[0.06] rounded-xl p-[1px] transition-all duration-300 hover:bg-white/[0.05] hover:border-[#C2410C]/30 hover:shadow-[0_0_25px_rgba(194,65,12,0.12)] group">
      <div class="bg-[#0d1117] rounded-[calc(0.75rem-1px)] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)] h-full">
        <div class="flex items-start gap-3">
          <span class="mt-0.5 w-1.5 h-1.5 rounded-full bg-[#C2410C] shrink-0" />
          <div>
            <h3 class="font-mono font-medium text-[#e6edf3] mb-1.5 text-sm">{threat.name}</h3>
            <p class="text-[#8b949e] text-xs leading-relaxed">{threat.description}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function Problem() {
  return (
    <section id="problem" class="py-24 px-4 max-w-6xl mx-auto">
      <h2 class="text-3xl font-semibold text-center mb-4">What AI coding agents introduce</h2>
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
