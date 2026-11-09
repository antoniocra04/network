# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Go (single static binary, html/template) + HTMX, SQLite for history. Runs in Docker on a Raspberry Pi 5 (linux/arm64) on the home network. All assets are served locally: the page must load when the outside internet is gone.

## Users

One person, the owner of a home network in Russia. They open the panel when something online behaves oddly (a site does not load, a messenger stalls, video crawls) and wants to know in seconds whether the problem is at home, at the ISP, inside the Russian segment, at the border, or with one particular service. They open it equally often from a phone (standing near the router, quick glance) and from a laptop (sitting down to dig into history and details).

## Product Purpose

Continuously watch the home connection and explain its state in plain words, so the owner never has to debug by hand. Success: one glance answers "what is broken and where", and history answers "since when and how often".

## Positioning

Not an uptime pinger. It diagnoses the Russian-specific failure modes: regional shutdowns, isolation of the Russian segment, whitelists, DNS substitution, SNI-based DPI blocks, the ~16 KB cut-off to foreign hosting, throttling, and services that themselves refuse Russian users. It tells these apart instead of showing one red light.

## Operating Context

- Self-hosted on a Pi 5 wired to the home router. Direct ISP route, no VPN on the router, no external VPS.
- Viewed over the LAN from phone and laptop browsers, often at the exact moment the internet is broken.
- No notifications: the owner comes to the panel, the panel does not come to them.

## Capabilities and Constraints

- Layered checks: Pi itself, home (router), ISP, Russian internet, foreign internet, individual services, protocols.
- Per-service block classification: DNS substitution, IP block, SNI DPI, ~16 KB cut-off, throttling, geo-refusal by the service itself.
- Verdict in one sentence at the top, incidents with diagnostic snapshots, 24 h timeline, daily availability calendar.
- On-demand check of any domain with the steps shown as they run.
- Gaps when the Pi was off are shown as "no data", never as an outage.
- Lightweight: low memory, no JS frameworks, server-rendered SVG charts.

## Brand Commitments

- Name: «Связь».
- Interface language: Russian.
- Voice: plain, specific, human. No marketing tone, no exclamation marks, no emoji, no filler like «Всё отлично!» or «Мы заботимся о…». Copy must not read as AI-written. State facts: what, where, since when.
- Feel requested by the owner: an instrument panel. Dense, numbers first, monospaced figures for data.

## Evidence on Hand

None beyond live measurements the app collects itself. No invented history or statistics.

## Product Principles

- Answer first, details second: the verdict sentence leads every visit.
- Name the layer: always say where the break is, not just that something is broken.
- Distinguish kinds of failure: an outage, a block, a slowdown and a service's own refusal are different statements.
- Honest about uncertainty: when a conclusion is a guess, say so; when there is no data, say that.
- Works when nothing else does: no external dependencies at render time.

## Accessibility & Inclusion

Status is never carried by color alone: every state also has a word and a shape. Body text meets WCAG AA contrast in both light and dark themes. Respect reduced motion.

## Standing visual preference

The owner chose the category standard over distinctive directions: a dark monitoring dashboard in the familiar shape of Uptime Kuma / Grafana-class tools, executed at the craft level of Linear and Vercel. Convention is the commitment; no novelty motifs.
