#!/usr/bin/env python3
"""Local visual tokens for the standalone Codex report."""

REPORT_CSS = r"""
:root{--paper:#F0F0EE;--ink:#1F1E1C;--muted:#8F8E86;--faint:#C0BFB7;--grid:rgba(31,30,28,.16);--soft:#DBDAD3;--safe:#43593B;--bad:#F5572F}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--paper);color:var(--ink);font-family:Inter,-apple-system,BlinkMacSystemFont,"SF Pro SC","PingFang SC",sans-serif;
  -webkit-font-smoothing:antialiased;line-height:1.55;padding:48px 28px 90px}
.page{max-width:1320px;margin:auto}
.masthead{margin-bottom:42px;padding:0 4px}
.eyebrow,.source,.tag{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.masthead h1{font-size:42px;line-height:1.08;letter-spacing:-.055em;font-weight:800}
.masthead p{max-width:720px;color:var(--muted);font-size:13px;margin-top:10px}
.hero{display:grid;grid-template-columns:1.35fr .65fr;gap:34px;margin-bottom:48px}
.hero-main,.hero-side{padding:25px 0;border-top:1px solid var(--ink);border-bottom:1px solid var(--grid)}
.hero-label{font-size:18px;color:var(--ink);font-weight:700;letter-spacing:-.02em}
.hero-number{font-size:82px;font-weight:800;letter-spacing:-.075em;line-height:.98;margin-top:8px;color:var(--safe)}
.hero-number small{font-size:22px;letter-spacing:-.02em;margin-left:5px}
.hero-meta{font-size:12px;color:var(--muted);margin-top:10px}
.hero-side{display:flex;flex-direction:column;justify-content:center}
.hero-side strong{font-size:29px;letter-spacing:-.045em}
.good{color:var(--safe)}.bad{color:var(--bad)}
.hero-side p{font-size:12px;color:var(--muted);margin-top:6px}
.hero-side .rule{height:1px;background:var(--grid);margin:14px 0}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:34px;margin-bottom:48px}
.card{padding:34px 34px 28px;background:rgba(255,255,255,.18);border-radius:24px}
.card.wide{grid-column:1/-1}
.card.square{aspect-ratio:1/1;display:flex;flex-direction:column}
.card.square>svg{flex:1;height:auto;min-height:0}
.card h2{font-size:21px;line-height:1.2;letter-spacing:-.03em;font-weight:700;margin:8px 0 12px}
.sub{font-size:11.5px;color:var(--muted);margin-bottom:12px}
.src{font-size:9.5px;color:var(--faint);letter-spacing:.1em;font-weight:600;margin-top:8px}
svg{width:100%;display:block;overflow:visible}
.chart-wide{height:380px}.chart-square{height:390px}.chart-history{height:390px}.chart-lens{height:390px}
svg text{font-family:Inter,-apple-system,BlinkMacSystemFont,"SF Pro SC","PingFang SC",sans-serif}
.rule-line{stroke:var(--grid);stroke-width:1}
.hair{stroke:var(--ink);stroke-width:.8;fill:none}
.hair-muted{stroke:var(--faint);stroke-width:.8;fill:none}
.ink{stroke:var(--ink);fill:var(--ink)}.muted{stroke:var(--muted);fill:var(--muted)}
.dash{stroke-dasharray:2.5 3}
.reveal{animation:rise var(--reveal-duration,2.1s) var(--reveal-ease,cubic-bezier(.2,.7,.3,1)) both;animation-play-state:paused}
.reveal.motion-loaded{animation-play-state:running}
.delay-1{animation-delay:.24s}.delay-2{animation-delay:.48s}.delay-3{animation-delay:.72s}
.lens-card .reveal{animation-duration:var(--reveal-duration,6.3s)}
.gauge-tick-path{fill:none;stroke-linecap:butt;stroke-linejoin:round}
.gauge-tick.reveal{animation-name:gauge-fade;animation-duration:.9s;animation-timing-function:ease;transform:none}
@keyframes gauge-fade{from{opacity:0}to{opacity:1}}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-delay:0!important;scroll-behavior:auto!important}}
.section{margin:34px 0}.section-head{display:flex;align-items:baseline;justify-content:space-between;border-bottom:1px solid var(--ink);padding-bottom:9px;margin-bottom:12px}
.section h2{font-size:18px;letter-spacing:-.025em}.section-head .source{font-size:9px}
.scope-visual{border-top:1px solid var(--grid);border-bottom:1px solid var(--grid);padding:16px 0 12px;margin:12px 0 14px}.scope-row{display:grid;grid-template-columns:128px 1fr 76px;align-items:center;gap:12px;margin:12px 0}.scope-name{font-size:11px;font-weight:700}.scope-path{display:block;color:var(--muted);font:9px ui-monospace,SFMono-Regular,Menlo,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:2px}.scope-track{height:16px;background:rgba(31,30,28,.08);border-radius:999px;overflow:hidden}.scope-fill{height:100%;border-radius:999px;background:var(--ink);min-width:7px}.scope-row.other .scope-fill{background:var(--muted)}.scope-row.shared .scope-fill{background:var(--faint)}.scope-row.free .scope-fill{background:var(--safe)}.scope-value{text-align:right;font-size:11px;font-variant-numeric:tabular-nums;font-weight:700}.scope-legend{display:flex;justify-content:space-between;color:var(--muted);font-size:10px;margin-top:10px}.scope-legend b{color:var(--ink)}.scope-note{color:var(--muted);font-size:11px;margin-top:8px}
.scope-fill.reveal{animation-name:scope-grow;animation-duration:var(--scope-duration,2.1s);animation-timing-function:cubic-bezier(.16,1,.3,1);transform-origin:left center}
@keyframes scope-grow{from{opacity:0;transform:scaleX(0)}to{opacity:1;transform:scaleX(1)}}
.diverge-bar.reveal{animation-name:diverge-grow;animation-duration:var(--diverge-duration,2.1s);animation-timing-function:cubic-bezier(.16,1,.3,1);transform-box:fill-box;transform-origin:var(--diverge-origin,left center)}
.diverge-bar.negative{--diverge-origin:right center}
@keyframes diverge-grow{from{opacity:0;transform:scaleX(0)}to{opacity:1;transform:scaleX(1)}}
.history-segment.reveal{animation-name:history-draw;animation-duration:var(--history-segment-duration,.84s);animation-timing-function:cubic-bezier(.22,.82,.35,1);stroke-dasharray:1;stroke-dashoffset:1}
.history-node.reveal{animation-name:history-node-in;animation-duration:.12s;animation-timing-function:ease-out;transform:none}
@keyframes history-draw{from{stroke-dashoffset:1}to{stroke-dashoffset:0}}
@keyframes history-node-in{from{opacity:0}to{opacity:1}}
.table-wrap{overflow-x:auto}.table{width:100%;border-collapse:collapse;min-width:760px}
.table th,.table td{padding:11px 10px;border-bottom:1px solid var(--grid);text-align:left;font-size:12px;vertical-align:top}
.table th{font-size:9px;letter-spacing:.1em;color:var(--muted);text-transform:uppercase}.table-action{text-align:right!important;white-space:nowrap}
.table td.num{font-variant-numeric:tabular-nums;font-weight:700;white-space:nowrap}.path{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);word-break:break-all}
.insight{font-size:14px;max-width:850px;margin-bottom:13px}.list{padding-left:20px;color:var(--muted);font-size:13px}.list li{margin:5px 0}
.tier{margin:24px 0}.tier-head{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;border-bottom:1px solid var(--grid);padding-bottom:9px;margin-bottom:9px}.tier-head h3{font-size:15px;margin:0}.tier-intro{color:var(--muted);font-size:12px;line-height:1.5;margin:5px 0 0;max-width:780px}.tier-head-meta{display:flex;flex-direction:column;align-items:flex-end;gap:8px}.tier-total{font-size:13px;font-weight:700;color:var(--ink);white-space:nowrap}.tier-actions{display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end}.tier-actions .action-btn{white-space:nowrap}.tier-actions .action-note{white-space:nowrap}.item{border-bottom:1px solid var(--grid);padding:13px 0}.item summary{cursor:pointer;list-style:none;display:flex;gap:10px;align-items:baseline}.item summary::-webkit-details-marker{display:none}
.item{border-bottom:1px solid var(--grid);padding:13px 0}.item summary{cursor:pointer;list-style:none;display:flex;gap:10px;align-items:baseline}.item summary::-webkit-details-marker{display:none}
.item summary:before{content:"＋";font-size:14px;color:var(--muted);width:16px}.item[open] summary:before{content:"−"}
.item-name{font-weight:700;flex:1;min-width:180px}.item-explainer{display:block;color:var(--muted);font-size:11px;font-weight:400;line-height:1.45;margin-top:3px;max-width:900px}.item-meter{display:flex;justify-content:flex-end;flex:0 0 260px;width:260px;min-width:260px;height:9px;background:transparent;border-radius:999px;overflow:hidden;align-self:center}.item-meter-fill{display:block;height:100%;min-width:3px;border-radius:999px;background:#8F8E86}.item-size{flex:0 0 88px;text-align:right;font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.item-body{padding:12px 0 0 26px;color:var(--muted);font-size:13px}.item-body p{margin:7px 0}.label{font-size:10px;color:var(--faint);font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-top:12px}
.code{position:relative;background:var(--ink);color:var(--paper);padding:13px 48px 13px 13px;border-radius:10px;font:11px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;overflow:auto;margin-top:6px;white-space:pre-wrap;word-break:break-word}
.copy{position:absolute;right:8px;top:8px;border:0;border-radius:7px;background:var(--paper);color:var(--ink);padding:4px 8px;font-size:10px;cursor:pointer}
.action-row{display:flex;gap:7px;flex-wrap:wrap;margin:12px 0 5px}.action-btn{border:1px solid var(--faint);background:transparent;color:var(--ink);border-radius:999px;padding:6px 10px;font-size:11px;cursor:pointer}.action-btn:hover,.action-btn.danger{border-color:var(--ink);color:var(--ink)}.action-btn:disabled{opacity:.45;cursor:not-allowed}.action-btn:disabled:hover{border-color:var(--faint);color:var(--ink)}.action-note{font-size:11px;color:var(--muted);padding:7px 0}
.note{color:var(--muted);font-size:12px}.denied{border-top:1px solid var(--ink);padding-top:13px;color:var(--muted);font-size:12px;word-break:break-all}
.permission-panel{border-top:1px solid var(--ink);border-bottom:1px solid var(--grid);padding:18px 0;margin:28px 0}.permission-panel h2{font-size:18px;margin:0 0 7px}.permission-summary{font-size:13px;font-weight:700}.permission-panel ol{padding-left:22px;margin:12px 0;color:var(--ink);font-size:12px}.permission-panel li{margin:6px 0}.permission-note{color:var(--muted);font-size:12px;max-width:920px}.permission-paths{margin-top:12px;color:var(--muted);font-size:11px}.permission-paths summary{cursor:pointer;font-weight:700;color:var(--ink)}.permission-paths code{display:block;margin-top:6px;font:10px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.footer{margin-top:46px;padding-top:12px;border-top:1px solid var(--grid);color:var(--faint);font-size:10px;letter-spacing:.08em;text-transform:uppercase}
.deferred-sentinel{height:1px;width:100%;pointer-events:none}
@media(max-width:760px){body{padding:30px 16px 60px}.masthead h1{font-size:31px}.hero{grid-template-columns:1fr;gap:0}.hero-side{border-top:0}.chart-grid{grid-template-columns:1fr}.card.wide{grid-column:auto}.hero-number{font-size:64px}.scope-row{grid-template-columns:96px 1fr 60px;gap:7px}.scope-path{font-size:8px}.tier-head{display:block}.tier-head-meta{align-items:flex-start;margin-top:10px}.tier-actions{justify-content:flex-start}.item summary{flex-wrap:wrap}.item-name{min-width:140px}.item-meter{flex:1 1 150px;min-width:130px}.item-size{flex:0 0 76px}}
@media(prefers-color-scheme:dark){.item-meter{background:transparent;box-shadow:none}.item-meter-fill{background:#C0C0B7}}
"""
