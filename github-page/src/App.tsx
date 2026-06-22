import Hero from './components/Hero'
import Problem from './components/Problem'
import TerminalDemo from './components/TerminalDemo'
import Architecture from './components/Architecture'
import Footer from './components/Footer'
import './index.css'

export default function App() {
  return (
    <div class="min-h-screen bg-[#0d1117] text-[#e6edf3]">
      <Hero />
      <Problem />
      <TerminalDemo />
      <Architecture />
      <Footer />
    </div>
  )
}
