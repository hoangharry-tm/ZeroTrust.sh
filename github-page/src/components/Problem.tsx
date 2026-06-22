const threats = [
  {
    name: 'Package hallucinations',
    description: "An agent imports `requests-auth-aws` (non-existent). An attacker registers it with a payload. Your scanner sees nothing — the package isn't on any CVE list yet.",
  },
  {
    name: 'Prompt injection in source',
    description: 'Adversarial instructions in comments, docstrings, or string literals that redirect the next agent that reads this file.',
  },
  {
    name: 'Security-node disappearance',
    description: 'An auth check is present in commit N, silently absent in commit N+1. Functional tests still pass. No diff alert fires.',
  },
  {
    name: 'Instruction file backdoors',
    description: 'Unicode obfuscation (U+202E, U+200B) buried in `CLAUDE.md`, `.cursor/rules`, `AGENTS.md`, or MCP configs. No competitor scans this surface.',
  },
  {
    name: 'Agent cheat patterns',
    description: '`return True` in `*auth*` functions. `TODO: add auth` with no follow-through. Disabled assertions that make the test suite green.',
  },
  {
    name: 'MCP server config injection',
    description: 'External URLs, shell/execute capabilities, and over-broad filesystem scopes injected into `.mcp.json`.',
  },
]

export default function Problem() {
  return (
    <section class="py-20 px-4 max-w-6xl mx-auto">
      <h2 class="text-3xl font-semibold text-center mb-12">What AI coding agents introduce</h2>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        {threats.map((threat) => (
          <div class="bg-[#161b22] border-l-4 border-[#f85149] rounded-md p-6">
            <h3 class="font-mono font-medium text-[#e6edf3] mb-2">{threat.name}</h3>
            <p class="text-[#8b949e] text-sm leading-relaxed">{threat.description}</p>
          </div>
        ))}
      </div>
    </section>
  )
}
