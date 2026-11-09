# Design

The category standard, executed carefully: a dark monitoring dashboard. Familiar shape (sidebar, panels, tables), with the product's own logic on top: a one-sentence verdict first, then the route by layers.

## Tokens

All colours are OKLCH, defined in `internal/web/static/app.css` `:root`.

| Role | Value |
|---|---|
| Ground | `--bg` oklch(0.165 0.006 260) |
| Sidebar | `--side` oklch(0.145 0.006 260) |
| Panel / raised | `--panel` 0.198, `--panel-2` 0.228 |
| Hairlines | `--line` 0.285, `--line-soft` 0.245 |
| Text | `--text` 0.955, `--muted` 0.76, `--faint` 0.66 |
| Accent (focus, selection) | `--accent` oklch(0.74 0.12 252) |
| Status | `--ok` 0.76 0.15 152, `--warn` 0.83 0.15 80, `--fail` 0.68 0.19 24, `--none` 0.42 |
| Chart series | categorical slots 1–3: `#3987e5`, `#d95926`, `#199e70` |

Status is never colour alone: every state has an icon shape (check in circle, triangle, cross in circle, dashed ring) and a word.

## Type

System sans (`system-ui` stack) for everything; system mono only for addresses, hosts and timings. Tabular numerals everywhere. Scale: 11 / 12 / 13 / 14 (body) / 15 / 20–24 (verdict, page titles). Weights 400, 500, 600.

## Components

- Panel: `--panel`, 1px `--line-soft` border, 10px radius, no shadow.
- Verdict: panel tinted with the status colour at 10–12% alpha.
- Route: six layers in a row (3×2 on phones), icon + connector line coloured by status.
- Check tables: fixed layout, name / summary / value / time; on phones each row becomes a two-line block.
- Timeline and calendar: flat cells, status fills, grey for "no data".
- Charts: one fixed log scale (1 ms – 1 s) on every chart, HTML axis labels, loss as ticks on the baseline, native `<title>` tooltips per bucket.

## Motion

150–220 ms, `cubic-bezier(0.22, 1, 0.36, 1)`. Only state: nav hover, new check steps sliding in, the verdict on live swap. Disabled under `prefers-reduced-motion`.

## Voice

Russian, plain, specific. State what broke, where, since when. No exclamation marks, no emoji, no reassurance filler.
