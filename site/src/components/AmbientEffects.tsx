import { createSignal, onCleanup } from 'solid-js'

export default function AmbientEffects() {
  const [mouseX, setMouseX] = createSignal(50)
  const [mouseY, setMouseY] = createSignal(50)

  function handleMouseMove(e: MouseEvent) {
    setMouseX((e.clientX / window.innerWidth) * 100)
    setMouseY((e.clientY / window.innerHeight) * 100)
  }

  if (typeof window !== 'undefined') {
    window.addEventListener('mousemove', handleMouseMove)
    onCleanup(() => window.removeEventListener('mousemove', handleMouseMove))
  }

  return (
    <div class="pointer-events-none fixed inset-0 z-0">
      <div
        class="absolute inset-0"
        style={{
          background: `radial-gradient(600px circle at ${mouseX()}% ${mouseY()}%, rgba(194,65,12,0.04), transparent 60%)`,
        }}
      />
      <div class="absolute -top-32 -left-32 w-96 h-96 rounded-full bg-[#C2410C]/[0.06] blur-3xl animate-float-slow" />
      <div class="absolute -bottom-40 -right-32 w-[30rem] h-[30rem] rounded-full bg-[#58a6ff]/[0.04] blur-3xl animate-float-slower" />
    </div>
  )
}
