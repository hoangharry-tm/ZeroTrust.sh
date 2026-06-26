export default function Hero() {
  return (
    <section
      id="hero"
      class="relative flex flex-col items-center justify-center min-h-screen px-4 text-center py-20 overflow-hidden"
    >
      <h1 class="font-mono text-5xl md:text-7xl font-bold mb-4">
        <span class="bg-linear-to-r from-[#58a6ff] via-[#818cf8] to-[#8b5cf6] bg-clip-text text-transparent animate-gradient-shift">ZeroTrust.sh</span>
      </h1>
      <p class="text-xl md:text-2xl text-[#e6edf3] mb-2 max-w-2xl">
        Local, offline vulnerability scanner for source code. Deeper than SAST.
      </p>
      <p class="text-[#8b949e] mb-8 max-w-xl">
        Source never leaves your machine. No VCS token. No cloud upload. No trust.
      </p>
      <div class="flex gap-4 mb-8 flex-wrap justify-center">
        <a
          href="https://github.com/hoangharry-tm/ZeroTrust.sh"
          target="_blank"
          rel="noopener noreferrer"
          class="group relative px-8 py-3.5 rounded-full font-semibold text-sm transition-all duration-300 bg-[#C2410C]/10 backdrop-blur-xl border border-[#C2410C]/30 text-[#C2410C] hover:bg-[#C2410C]/20 hover:border-[#C2410C]/50 shadow-[inset_0_1px_0_rgba(255,255,255,0.15)] hover:shadow-[0_0_25px_rgba(194,65,12,0.3)] active:scale-[0.98]"
        >
          <span class="flex items-center gap-2">
            ⭐ Star on GitHub
            <span class="w-6 h-6 rounded-full bg-[#C2410C]/20 flex items-center justify-center text-xs transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5">→</span>
          </span>
        </a>
        <a
          href="#architecture"
          class="group relative px-8 py-3.5 rounded-full font-semibold text-sm transition-all duration-300 bg-white/[0.03] backdrop-blur-xl border border-white/[0.08] text-[#e6edf3] hover:bg-white/[0.06] hover:border-white/[0.15] shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] active:scale-[0.98]"
        >
          <span class="flex items-center gap-2">
            View Architecture
            <span class="w-6 h-6 rounded-full bg-white/[0.08] flex items-center justify-center text-xs transition-transform duration-300 group-hover:translate-x-0.5">→</span>
          </span>
        </a>
      </div>
      <div class="flex gap-3 font-mono text-sm flex-wrap justify-center">
        <span class="px-3 py-1.5 border border-[#f85149]/40 text-[#f85149] rounded-full animate-glow-pulse">[BLOCK]</span>
        <span class="px-3 py-1.5 border border-[#d29922]/40 text-[#d29922] rounded-full animate-glow-pulse-slow">[HIGH]</span>
        <span class="px-3 py-1.5 border border-[#58a6ff]/30 text-[#58a6ff] rounded-full">[MEDIUM]</span>
        <span class="px-3 py-1.5 border border-[#8b949e]/30 text-[#8b949e] rounded-full">[LOW]</span>
      </div>
    </section>
  )
}
