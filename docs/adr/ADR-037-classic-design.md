# ADR-037: A classic, ledger-style design instead of the default dark-dashboard look

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "the design looks so AI / I WANT IT TO BE CLASSIC AND ELEGANT")

## Context

The frontend's theme (`app/globals.css`, set up at project start) was a generic dark-SaaS look: neon
cyan accent (`#22d3ee`) on near-black, a single sans typeface (Geist) for everything including
headings, `rounded-xl`/`rounded-lg` pill-shaped cards and buttons, and uppercase letter-spaced micro
labels for card titles and the sidebar wordmark. The owner read this as looking generic/AI-generated.

## Decision

Change design tokens and the shared components only -- not individual pages -- so the change applies
everywhere at once:

- **Palette** (`app/globals.css`): ink background, warm parchment foreground, a muted antique-brass
  accent replacing neon cyan, and desaturated severity colours (brick/ochre/muted-gold/steel-blue/slate
  instead of saturated rose/orange/yellow/blue).
- **Type**: added `Source Serif 4` (`app/layout.tsx`, `--font-serif`) for `h1`-`h3` and the "SecureAgent"
  wordmark; body text stays on the existing sans. Serif headline + sans body is the classic/editorial
  pairing the owner was asking for, not a full font replacement.
- **Shape**: `rounded-xl`/`rounded-lg` throughout (`components/ui.tsx`, `Sidebar.tsx`, `AuthShell.tsx`,
  the audit/run pages) down to `rounded-sm`; the sidebar's active-link highlight changed from a filled
  cyan background to a left hairline rule, closer to a ledger/document nav than a dashboard pill.
- **Button**: was a solid filled cyan button; now bordered/outlined in the accent colour, filling on
  hover -- quieter by default, same as a classic UI control rather than a call-to-action chip.
- Card titles: dropped the "uppercase tracking-wider text-muted" micro-label treatment for a serif
  section heading with a hairline rule underneath.

## Verification

Rebuilt and ran the frontend in Docker, logged into the real app with the live Mistral-reviewed audit
from ADR-033 still present, and screenshotted login, dashboard, `/run`, the audit list, and an audit
detail page with all five severities showing. `npx tsc --noEmit`, `eslint`, `vitest run` (40/40) and
`next build` all clean.

## Not claimed

This is a visual pass, not a redesign of layout or information architecture -- the same pages, same
components, same data. "Classic and elegant" is a judgement call the owner made; no A/B test or user
research backs the specific palette/type choices.
