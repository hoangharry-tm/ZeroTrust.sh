import { createVisibilityObserver } from "@solid-primitives/intersection-observer"
import { createSignal, type JSX } from "solid-js"

export function ScrollReveal(props: {
  children: JSX.Element
  class?: string
  delay?: number
  threshold?: number
}) {
  const useObserver = createVisibilityObserver({ threshold: props.threshold ?? 0.15 })
  const [target, setTarget] = createSignal<Element>()
  const visible = useObserver(target)

  return (
    <div
      ref={setTarget}
      class={`transition-all duration-700 ease-out motion-reduce:transition-none ${
        props.class ?? ""
      } ${visible() ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`}
      style={{ "transition-delay": `${props.delay ?? 0}ms` }}
    >
      {props.children}
    </div>
  )
}

export function createStaggerDelay(index: number, baseDelay = 100): number {
  return index * baseDelay
}
