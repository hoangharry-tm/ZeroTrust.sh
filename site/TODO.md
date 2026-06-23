# ZeroTrust.sh GitHub Page — UI/UX Enhancements

## Stack
Solid JS + Tailwind CSS v4 + ShadCn (`@kobalte/core`)

---

## Pass 1 — Scroll Reveals, BG Patterns, Gradient Hero, Badge Pulses, CTA Polish ✅

- [x] Install `@solid-primitives/intersection-observer`
- [x] Create `src/primitives/scrollReveal.tsx`
- [x] Add dot grid + gradient keyframes + badge pulse animations to `index.css`
- [x] Wrap sections in App.tsx with ScrollReveal
- [x] Animated gradient text on "ZeroTrust.sh" hero heading
- [x] Pulsing glow on severity badges
- [x] CTA hover polish — green CTA glow+scale, border CTA arrow slide

## Pass 2 — Ambient Orbs, Mouse Spotlight, Card Hover, Metrics Counter ✅

- [x] Ambient gradient orbs behind Hero
- [x] Mouse-tracking spotlight effect on Hero
- [x] Threat card hover — scale, border widen, red glow
- [x] `MetricsCounter.tsx` — animated "1,247 scanned · 34 changed · 3 findings"
- [x] Terminal scan-line overlay + typewriter timing polish

## Pass 3 — Sticky Nav, Noise Grain, Native Architecture Diagram ✅

- [x] `Nav.tsx` — sticky nav bar slides in on scroll past 70vh
- [x] Noise/grain texture overlay (SVG feTurbulence, opacity 0.02)
- [x] `ArchitectureTabs.tsx` — `@kobalte/core/tabs` replacing iframe (4 tabs: Ingestion, Path A, Path B, Output)
- [x] `prefers-reduced-motion` respected throughout
- [x] Dead files cleaned: `index.tsx`, `App.css`, `assets/` (solid.svg, vite.svg, hero.png)

---

## Final Summary

### Files created (5)
- `src/primitives/scrollReveal.tsx`
- `src/components/Nav.tsx`
- `src/components/MetricsCounter.tsx`
- `src/components/ArchitectureTabs.tsx`

### Dependencies added (2)
- `@solid-primitives/intersection-observer`
- `@kobalte/core` (already present, newly used)

### Files modified (7)
- `index.css`, `index.html`, `App.tsx`, `Hero.tsx`, `Problem.tsx`, `TerminalDemo.tsx`, `Architecture.tsx`

### Files removed (5)
- `src/index.tsx`, `src/App.css`, `src/assets/solid.svg`, `src/assets/vite.svg`, `src/assets/hero.png`
