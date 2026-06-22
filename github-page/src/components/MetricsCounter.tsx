import { createSignal, createEffect, onCleanup } from 'solid-js'
import { createVisibilityObserver } from '@solid-primitives/intersection-observer'

const stats = [
  { label: 'Files scanned', value: 1247, suffix: '' },
  { label: 'Changed', value: 34, suffix: '' },
  { label: 'Findings', value: 3, suffix: '' },
]

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

  const c1 = useAnimatedCount(stats[0].value, visible)
  const c2 = useAnimatedCount(stats[1].value, visible)
  const c3 = useAnimatedCount(stats[2].value, visible)

  const counts = [c1, c2, c3]

  return (
    <section
      id="metrics"
      ref={ref}
      class="py-16 px-4 max-w-4xl mx-auto"
    >
      <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
        {stats.map((stat, i) => (
          <div class="text-center">
            <div class="font-mono text-4xl md:text-5xl font-bold text-[#3fb950] tabular-nums">
              {visible() ? counts[i]() : 0}
              {stat.suffix}
            </div>
            <div class="text-[#8b949e] text-sm mt-2 font-mono">{stat.label}</div>
          </div>
        ))}
      </div>
    </section>
  )
}
