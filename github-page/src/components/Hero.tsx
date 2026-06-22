export default function Hero() {
  return (
    <section class="flex flex-col items-center justify-center min-h-screen px-4 text-center py-20">
      <h1 class="font-mono text-5xl md:text-7xl font-bold text-[#e6edf3] mb-4">
        ZeroTrust.sh
      </h1>
      <p class="text-xl md:text-2xl text-[#e6edf3] mb-2 max-w-2xl">
        Local, offline SAST for code written by AI coding agents.
      </p>
      <p class="text-[#8b949e] mb-8 max-w-xl">
        Source never leaves your machine. No VCS token. No cloud upload. No trust.
      </p>
      <div class="flex gap-4 mb-8 flex-wrap justify-center">
        <a
          href="https://github.com/hoangharry-tm/ZeroTrust.sh"
          target="_blank"
          rel="noopener noreferrer"
          class="px-6 py-3 bg-[#3fb950] text-[#0d1117] font-semibold rounded-md hover:opacity-90 transition-opacity"
        >
          ⭐ Star on GitHub
        </a>
        <a
          href="#architecture"
          class="px-6 py-3 border border-[#30363d] text-[#e6edf3] rounded-md hover:bg-[#161b22] transition-colors"
        >
          View Architecture
        </a>
      </div>
      <div class="flex gap-3 font-mono text-sm flex-wrap justify-center">
        <span class="px-2 py-1 border border-[#f85149] text-[#f85149] rounded">[BLOCK]</span>
        <span class="px-2 py-1 border border-[#d29922] text-[#d29922] rounded">[HIGH]</span>
        <span class="px-2 py-1 border border-[#58a6ff] text-[#58a6ff] rounded">[MEDIUM]</span>
        <span class="px-2 py-1 border border-[#8b949e] text-[#8b949e] rounded">[LOW]</span>
      </div>
    </section>
  )
}
