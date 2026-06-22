import { createSignal, onMount, onCleanup } from 'solid-js'

const links = [
  { label: 'Problem', href: '#problem' },
  { label: 'Demo', href: '#demo' },
  { label: 'Architecture', href: '#architecture' },
]

export default function Nav() {
  const [visible, setVisible] = createSignal(false)
  const [active, setActive] = createSignal('')

  onMount(() => {
    const onScroll = () => {
      setVisible(window.scrollY > window.innerHeight * 0.7)
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    onCleanup(() => window.removeEventListener('scroll', onScroll))

    const targets = document.querySelectorAll<HTMLElement>('section[id]')
    const observer = new IntersectionObserver(
      (entries) => {
        let closest: string | undefined
        let closestTop = Infinity
        for (const entry of entries) {
          if (entry.isIntersecting) {
            const top = entry.boundingClientRect.top
            if (top < closestTop) {
              closestTop = top
              closest = entry.target.id
            }
          }
        }
        if (closest) setActive(closest)
      },
      { threshold: 0.2 }
    )
    targets.forEach((s) => observer.observe(s))
    onCleanup(() => observer.disconnect())
  })

  return (
    <nav
      class={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        visible() ? 'translate-y-0 opacity-100' : '-translate-y-full opacity-0'
      }`}
    >
      <div class="backdrop-blur-md bg-[#0d1117]/80 border-b border-[#30363d]">
        <div class="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
          <a
            href="#hero"
            class="font-mono text-sm text-[#e6edf3] font-medium hover:text-[#3fb950] transition-colors"
          >
            ZeroTrust.sh
          </a>
          <div class="flex items-center gap-6">
            {links.map((link) => (
              <a
                href={link.href}
                class={`text-sm transition-colors ${
                  active() === link.href.slice(1)
                    ? 'text-[#e6edf3]'
                    : 'text-[#8b949e] hover:text-[#e6edf3]'
                }`}
              >
                {link.label}
              </a>
            ))}
            <a
              href="https://github.com/hoangharry-tm/ZeroTrust.sh"
              target="_blank"
              rel="noopener noreferrer"
              class="text-[#8b949e] hover:text-[#e6edf3] transition-colors"
            >
              <svg viewBox="0 0 19 19" class="w-4 h-4 fill-current" aria-label="GitHub">
                <path
                  fill-rule="evenodd"
                  d="M9.356 1.85C5.05 1.85 1.57 5.356 1.57 9.694a7.84 7.84 0 0 0 5.324 7.44c.387.079.528-.168.528-.376 0-.182-.013-.805-.013-1.454-2.165.467-2.616-.935-2.616-.935-.349-.91-.864-1.143-.864-1.143-.71-.48.051-.48.051-.48.787.051 1.2.805 1.2.805.695 1.194 1.817.857 2.268.649.064-.507.27-.857.49-1.052-1.728-.182-3.545-.857-3.545-3.87 0-.857.31-1.558.8-2.104-.078-.195-.349-1 .077-2.078 0 0 .657-.208 2.14.805a7.5 7.5 0 0 1 1.946-.26c.657 0 1.328.092 1.946.26 1.483-1.013 2.14-.805 2.14-.805.426 1.078.155 1.883.078 2.078.502.546.799 1.247.799 2.104 0 3.013-1.818 3.675-3.558 3.87.284.247.528.714.528 1.454 0 1.052-.012 1.896-.012 2.156 0 .208.142.455.528.377a7.84 7.84 0 0 0 5.324-7.441c.013-4.338-3.48-7.844-7.773-7.844"
                  clip-rule="evenodd"
                />
              </svg>
            </a>
          </div>
        </div>
      </div>
    </nav>
  )
}
