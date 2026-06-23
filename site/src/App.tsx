import Nav from './components/Nav'
import Hero from './components/Hero'
import Problem from './components/Problem'
import MetricsCounter from './components/MetricsCounter'
import TerminalDemo from './components/TerminalDemo'
import Architecture from './components/Architecture'
import Footer from './components/Footer'
import AmbientEffects from './components/AmbientEffects'
import { ScrollReveal } from './primitives/scrollReveal'
import './index.css'

export default function App() {
  return (
    <div class="min-h-screen bg-[#0d1117] text-[#e6edf3] bg-dot-grid-body">
      <AmbientEffects />
      <Nav />
      <ScrollReveal threshold={0}>
        <Hero />
      </ScrollReveal>
      <ScrollReveal threshold={0.15}>
        <Problem />
      </ScrollReveal>
      <ScrollReveal threshold={0.15}>
        <MetricsCounter />
      </ScrollReveal>
      <ScrollReveal threshold={0.15}>
        <TerminalDemo />
      </ScrollReveal>
      <ScrollReveal threshold={0.15}>
        <Architecture />
      </ScrollReveal>
      <ScrollReveal threshold={0.1}>
        <Footer />
      </ScrollReveal>
    </div>
  )
}
