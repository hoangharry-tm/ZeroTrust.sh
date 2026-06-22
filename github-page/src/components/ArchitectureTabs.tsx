import { Tabs } from '@kobalte/core/tabs'

const pipeline = [
  {
    id: 'ingestion',
    label: 'Ingestion',
    content: (
      <div class="space-y-4">
        <p class="text-[#e6edf3] text-sm leading-relaxed">
          Two parallel integrity checks run before any analysis touches source code:
        </p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="bg-white/[0.03] border border-white/[0.06] rounded-xl p-[1px]">
            <div class="bg-[#0d1117] rounded-[calc(0.75rem-1px)] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]">
              <div class="font-mono text-xs text-[#3fb950] mb-1">MIV</div>
              <div class="font-mono text-xs text-[#8b949e]">
                Model Integrity Verifier — cosign/Sigstore Rekor signed registry.
                WARN for unrecognized models, BLOCK on hash mismatch.
              </div>
            </div>
          </div>
          <div class="bg-white/[0.03] border border-white/[0.06] rounded-xl p-[1px]">
            <div class="bg-[#0d1117] rounded-[calc(0.75rem-1px)] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]">
              <div class="font-mono text-xs text-[#58a6ff] mb-1">DI</div>
              <div class="font-mono text-xs text-[#8b949e]">
                Differential Indexer — tracks auth/validate/check AST nodes.
                Only changed files pass through, cutting repeat-scan cost ~80–95%.
              </div>
            </div>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: 'path-a',
    label: 'Path A',
    content: (
      <div class="space-y-4">
        <p class="text-[#e6edf3] text-sm leading-relaxed">
          <span class="font-mono text-[#3fb950]">Pattern Detection</span> — fast,
          parallel static analysis with LLM-corroborated findings.
        </p>
        <div class="flex flex-wrap gap-3">
          {['OpenGrep', 'ast-grep', 'Joern CPG Taint', 'LLM Verifier'].map((name) => (
            <span class="px-3 py-1.5 bg-white/[0.03] border border-white/[0.06] rounded-full text-xs font-mono text-[#8b949e]">
              {name}
            </span>
          ))}
        </div>
        <p class="text-[#8b949e] text-xs">
          High-confidence rules bypass directly to Dedup. All others go through
          CoD + SCoT + XGrammar-2 verification.
        </p>
      </div>
    ),
  },
  {
    id: 'path-b',
    label: 'Path B',
    content: (
      <div class="space-y-4">
        <p class="text-[#e6edf3] text-sm leading-relaxed">
          <span class="font-mono text-[#58a6ff]">Semantic Detection</span> — deep,
          three-tier cost funnel targeting hard-to-pattern vulnerabilities.
        </p>
        <div class="space-y-2">
          {[
            { tier: 'Tier 1 · Heuristic Targeting', desc: 'CPG surface selection + CVE enrichment + resource ID dataflow' },
            { tier: 'Tier 2 · UniXcoder Classifier', desc: 'CPU-only ML classification · ~95% file elimination target' },
            { tier: 'Tier 3 · Bounded LLM Scan', desc: 'ReAct agent, max 3 steps · budget-exhausted → SUPPRESSED' },
          ].map((item) => (
            <div class="bg-white/[0.03] border border-white/[0.06] rounded-xl p-[1px]">
              <div class="bg-[#0d1117] rounded-[calc(0.75rem-1px)] p-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]">
                <div class="font-mono text-xs text-[#d29922] mb-1">{item.tier}</div>
                <div class="font-mono text-xs text-[#8b949e]">{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    ),
  },
  {
    id: 'output',
    label: 'Output',
    content: (
      <div class="space-y-4">
        <p class="text-[#e6edf3] text-sm leading-relaxed">
          Findings from both paths merge at the <span class="font-mono text-[#e6edf3]">Dedup</span>{' '}
          stage. Cross-path confirmation adds a +15pp confidence boost.
        </p>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { label: 'BLOCK', color: '#f85149', desc: 'Exploitation confirmed' },
            { label: 'HIGH / MEDIUM', color: '#d29922', desc: 'SSVC-graded' },
            { label: 'SUPPRESSED', color: '#8b949e', desc: 'Budget exhausted' },
          ].map((item) => (
            <div class="bg-white/[0.03] border border-white/[0.06] rounded-xl p-[1px]">
              <div class="bg-[#0d1117] rounded-[calc(0.75rem-1px)] p-3 text-center shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]">
                <div class="font-mono text-xs" style={{ color: item.color }}>{item.label}</div>
                <div class="font-mono text-xs text-[#8b949e] mt-1">{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
        <p class="text-[#8b949e] text-xs">
          Final report: self-contained HTML dashboard with unified diff patches per finding.
        </p>
      </div>
    ),
  },
]

export default function ArchitectureTabs() {
  return (
    <Tabs defaultValue="ingestion" class="w-full">
      <Tabs.List class="flex border-b border-[#30363d] mb-6">
        {pipeline.map((tab) => (
          <Tabs.Trigger
            value={tab.id}
            class="px-4 py-2.5 text-sm font-mono text-[#8b949e] transition-colors hover:text-[#e6edf3] data-[selected]:text-[#e6edf3] data-[selected]:border-b-2 data-[selected]:border-[#3fb950] outline-none border-b-2 border-transparent"
          >
            {tab.label}
          </Tabs.Trigger>
        ))}
      </Tabs.List>
      {pipeline.map((tab) => (
        <Tabs.Content value={tab.id} class="tabs-content">
          {tab.content}
        </Tabs.Content>
      ))}
    </Tabs>
  )
}
