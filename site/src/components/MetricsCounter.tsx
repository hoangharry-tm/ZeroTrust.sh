import { createSignal, createEffect, onCleanup } from 'solid-js'
import { createVisibilityObserver } from '@solid-primitives/intersection-observer'

const productStats = [
  { label: 'Rules', value: 42, sub: 'zero false positives' },
  { label: 'Languages', value: 12, sub: 'from Python to Rust' },
  { label: 'Threat vectors', value: 5, sub: 'no competitor covers' },
]

const runStats = [
  { label: 'Files scanned', value: 1247, sub: 'full codebase traversal' },
  { label: 'Changed', value: 34, sub: 'differential delta detected' },
  { label: 'Findings', value: 3, sub: 'confirmed vulnerabilities' },
]

const allStats = [...productStats, ...runStats]

function useAnimatedCount(target: number, enabled: () => boolean) {
  const [count, setCount] = createSignal(0)

  createEffect(() => {
    if (!enabled()) return
    const duration = 1200
    const start = performance.now()
    let frameId: number

    function tick(now: number) {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setCount(Math.round(eased * target))
      if (progress < 1) {
        frameId = requestAnimationFrame(tick)
      }
    }

    frameId = requestAnimationFrame(tick)
    onCleanup(() => cancelAnimationFrame(frameId))
  })

  return count
}

export default function MetricsCounter() {
  let ref: HTMLDivElement | undefined
  const useObserver = createVisibilityObserver({ threshold: 0.4 })
  const visible = useObserver(() => ref)

  const c1 = useAnimatedCount(allStats[0].value, visible)
  const c2 = useAnimatedCount(allStats[1].value, visible)
  const c3 = useAnimatedCount(allStats[2].value, visible)
  const c4 = useAnimatedCount(allStats[3].value, visible)
  const c5 = useAnimatedCount(allStats[4].value, visible)
  const c6 = useAnimatedCount(allStats[5].value, visible)

  const counts = [c1, c2, c3, c4, c5, c6]

  return (
    <section id="metrics" ref={ref} class="py-16 px-4 max-w-4xl mx-auto">
      <div class="space-y-10">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
          {productStats.map((stat, i) => (
            <div class="text-center">
              <div class="font-mono text-4xl md:text-5xl font-bold text-[#818cf8] tabular-nums">
                {visible() ? counts[i]() : 0}
              </div>
              <div class="text-[#8b949e] text-sm mt-2 font-mono">{stat.label}</div>
              <div class="text-[#8b949e]/50 text-[10px] mt-0.5 font-mono tracking-tight">{stat.sub}</div>
            </div>
          ))}
        </div>

        <div class="flex items-center gap-4">
          <div class="h-px flex-1 bg-linear-to-r from-transparent via-[#30363d] to-transparent" />
          <span class="text-[#8b949e] text-[10px] font-mono uppercase tracking-widest select-none">Demo</span>
          <div class="h-px flex-1 bg-linear-to-r from-transparent via-[#30363d] to-transparent" />
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
          {runStats.map((stat, i) => (
            <div class="text-center">
              <div class="font-mono text-4xl md:text-5xl font-bold text-[#58a6ff] tabular-nums">
                {visible() ? counts[i + 3]() : 0}
              </div>
              <div class="text-[#8b949e] text-sm mt-2 font-mono">{stat.label}</div>
              <div class="text-[#8b949e]/50 text-[10px] mt-0.5 font-mono tracking-tight">{stat.sub}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
