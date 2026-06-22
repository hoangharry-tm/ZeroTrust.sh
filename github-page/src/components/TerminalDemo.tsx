import { createSignal, onMount, onCleanup } from 'solid-js'

const lines = [
  { text: '$ zerotrust scan ./my-project', type: 'prompt' },
  { text: '', type: 'blank' },
  { text: '  scanning 1,247 files...', type: 'normal' },
  { text: '  ✓  differential index: 34 changed', type: 'success' },
  { text: '', type: 'blank' },
  { text: '  [BLOCK]  prompt-injection    GN-003', type: 'block' },
  { text: '           .cursor/rules:14   confidence: 0.97', type: 'detail' },
  { text: '', type: 'blank' },
  { text: '  [HIGH]   slopsquatting       PY-007', type: 'high' },
  { text: '           requirements.txt:8  confidence: 0.91', type: 'detail' },
  { text: '', type: 'blank' },
  { text: '  [MEDIUM] hardcoded-secret    PY-002', type: 'medium' },
  { text: '           config/settings.py:43  confidence: 0.88', type: 'detail' },
  { text: '', type: 'blank' },
  { text: '  3 findings · report: zerotrust-report.html', type: 'summary' },
]

function colorLine(line: { text: string; type: string }) {
  if (line.type === 'block') {
    return (
      <span>
        {'  '}
        <span class="text-[#f85149]">[BLOCK]</span>
        <span class="text-[#e6edf3]">  prompt-injection    GN-003</span>
      </span>
    )
  }
  if (line.type === 'high') {
    return (
      <span>
        {'  '}
        <span class="text-[#d29922]">[HIGH]</span>
        <span class="text-[#e6edf3]">   slopsquatting       PY-007</span>
      </span>
    )
  }
  if (line.type === 'medium') {
    return (
      <span>
        {'  '}
        <span class="text-[#58a6ff]">[MEDIUM]</span>
        <span class="text-[#e6edf3]"> hardcoded-secret    PY-002</span>
      </span>
    )
  }
  if (line.type === 'detail') {
    const parts = line.text.split('confidence:')
    if (parts.length === 2) {
      return (
        <span>
          <span class="text-[#8b949e]">{parts[0]}confidence:</span>
          <span class="text-[#8b949e]">{parts[1]}</span>
        </span>
      )
    }
    return <span class="text-[#8b949e]">{line.text}</span>
  }
  if (line.type === 'prompt') return <span class="text-[#3fb950]">{line.text}</span>
  if (line.type === 'success') return <span class="text-[#3fb950]">{line.text}</span>
  if (line.type === 'summary') return <span class="text-[#e6edf3]">{line.text}</span>
  return <span class="text-[#e6edf3]">{line.text}</span>
}

export default function TerminalDemo() {
  const [displayedLines, setDisplayedLines] = createSignal<number>(0)
  const [cursor, setCursor] = createSignal(true)

  onMount(() => {
    let lineIndex = 0
    let animInterval: ReturnType<typeof setInterval>
    let cursorInterval: ReturnType<typeof setInterval>

    cursorInterval = setInterval(() => setCursor(c => !c), 530)

    function animate() {
      lineIndex = 0
      setDisplayedLines(0)
      animInterval = setInterval(() => {
        lineIndex++
        setDisplayedLines(lineIndex)
        if (lineIndex >= lines.length) {
          clearInterval(animInterval)
          setTimeout(animate, 2500)
        }
      }, 130)
    }

    animate()

    onCleanup(() => {
      clearInterval(animInterval)
      clearInterval(cursorInterval)
    })
  })

  return (
    <section id="demo" class="py-20 px-4 max-w-3xl mx-auto">
      <h2 class="text-3xl font-semibold text-center mb-12">See it in action</h2>
      <div class="rounded-lg overflow-hidden border border-[#30363d]">
        <div class="bg-[#161b22] px-4 py-3 flex items-center gap-2 border-b border-[#30363d]">
          <span class="w-3 h-3 rounded-full bg-[#f85149] inline-block"></span>
          <span class="w-3 h-3 rounded-full bg-[#d29922] inline-block"></span>
          <span class="w-3 h-3 rounded-full bg-[#3fb950] inline-block"></span>
          <span class="ml-2 text-[#8b949e] text-sm font-mono">zerotrust — zsh</span>
        </div>
        <div class="relative bg-[#0d1117] p-6 font-mono text-sm min-h-[320px]">
          <div class="absolute inset-0 bg-scan-line z-10" />
          <div class="relative z-0">
            {lines.slice(0, displayedLines()).map((line, i) => (
              <div class="leading-6">
                {colorLine(line)}
                {i === displayedLines() - 1 && (
                  <span class={`text-[#e6edf3] ${cursor() ? 'opacity-100' : 'opacity-0'}`}>_</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
