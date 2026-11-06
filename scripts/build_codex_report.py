#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the Codex-specific report with the main skill's visual grammar."""

from __future__ import annotations

import json
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from report_theme import REPORT_CSS

SKILL_ROOT = Path(__file__).resolve().parents[1]


def parent_css() -> str:
    """Return the bundled CSS; kept as a local compatibility name."""
    return REPORT_CSS


CUSTOM_CSS = r"""
.cleanup-hero{grid-template-columns:1.2fr .8fr}.cleanup-hero .hero-number{color:var(--ink)}
.cleanup-hero .hero-number .accent{color:var(--safe)}.cleanup-hero .hero-side strong{font-size:25px}
.cleanup-hero .hero-side .accent{color:var(--bad)}
.eyebrow{margin-bottom:9px}.scope-note{max-width:960px}.scope-note code{font:10px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--ink)}
.report-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border-top:1px solid var(--ink);border-bottom:1px solid var(--grid);margin:0 0 44px}
.report-stat{padding:16px 18px 15px 0;border-right:1px solid var(--grid);margin-right:18px}.report-stat:last-child{border-right:0;margin-right:0}
.report-stat b{display:block;font-size:24px;letter-spacing:-.045em;color:var(--ink)}.report-stat span{display:block;color:var(--muted);font-size:11px;margin-top:2px}
.report-stat.green b{color:var(--safe)}.report-stat.orange b{color:var(--bad)}
.chart-caption{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:11px;margin-top:8px}.chart-caption strong{color:var(--ink)}
.ledger-summary{display:grid;grid-template-columns:1.1fr .9fr;gap:28px;border-top:1px solid var(--ink);border-bottom:1px solid var(--grid);padding:22px 0;margin:22px 0 34px}.ledger-summary h2{font-size:19px;margin-bottom:7px}.ledger-summary p{color:var(--muted);font-size:12px;max-width:720px}.ledger-summary ul{padding-left:19px;color:var(--muted);font-size:12px}.ledger-summary li{margin:4px 0}
.scope-table{min-width:920px}.scope-table td,.scope-table th{padding-top:13px;padding-bottom:13px}.user-pill{font-weight:700}.user-home{display:block;color:var(--muted);font:10px ui-monospace,SFMono-Regular,Menlo,monospace;margin-top:2px;max-width:270px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.status-ok{color:var(--safe);font-weight:700}.status-warn{color:var(--bad);font-weight:700}.status-muted{color:var(--muted)}
.root-list{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}.root-chip{display:inline-block;border:1px solid var(--faint);border-radius:999px;padding:2px 7px;color:var(--muted);font:9px ui-monospace,SFMono-Regular,Menlo,monospace;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tier.regenerable{border-left:3px solid var(--safe);padding-left:18px}.tier.manual{border-left:3px solid var(--bad);padding-left:18px}.tier.protected{border-left:3px solid var(--faint);padding-left:18px}.tier .item:last-child{border-bottom:0}
.tier-kicker{font-size:9px;letter-spacing:.12em;color:var(--muted);text-transform:uppercase;margin-bottom:3px}.tier-kicker.green{color:var(--safe)}.tier-kicker.orange{color:var(--bad)}
.ledger-tag{display:inline-block;margin-left:8px;border:1px solid var(--faint);border-radius:999px;padding:1px 6px;font-size:9px;line-height:1.45;color:var(--muted);vertical-align:2px;font-weight:600}.ledger-tag.green{color:var(--safe);border-color:var(--safe)}.ledger-tag.orange{color:var(--bad);border-color:var(--bad)}
.compact-group{border-bottom:1px solid var(--grid)}.compact-group summary{cursor:pointer;list-style:none;display:flex;gap:10px;align-items:baseline;padding:13px 0}.compact-group summary::-webkit-details-marker{display:none}.compact-group summary:before{content:"＋";font-size:14px;color:var(--muted);width:16px}.compact-group[open] summary:before{content:"−"}.compact-group-title{font-weight:700;flex:1;min-width:180px}.compact-group-sub{display:block;color:var(--muted);font-size:11px;font-weight:400;line-height:1.45;margin-top:3px}.compact-group-total{flex:0 0 auto;text-align:right;font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}.compact-group-body{padding:0 0 0 26px;border-left:1px solid var(--faint);margin-left:7px}.compact-group-body>.compact-group{margin-left:0}
.item-body .meta-grid{display:grid;grid-template-columns:120px 1fr;gap:4px 12px;margin:11px 0 2px}.meta-grid dt{color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.08em}.meta-grid dd{color:var(--muted);font-size:12px;word-break:break-word}.meta-grid dd.path{font-size:11px}
.issue-panel{border-top:1px solid var(--ink);border-bottom:1px solid var(--grid);padding:17px 0;margin:30px 0}.issue-panel h2{font-size:18px;margin-bottom:7px}.issue-panel p,.issue-panel li{color:var(--muted);font-size:12px}.issue-panel ul{padding-left:19px;margin-top:8px}.issue-panel li{margin:4px 0}.protected-note{background:rgba(31,30,28,.04);padding:12px 14px;color:var(--muted);font-size:11px;margin-top:12px}
.empty-state{padding:30px 0;border-bottom:1px solid var(--grid);color:var(--muted);font-size:13px}
.diagnostic{border-top:1px solid var(--grid);border-bottom:1px solid var(--grid);padding:12px 0;margin:20px 0}.diagnostic>summary{cursor:pointer;font-weight:700;color:var(--ink)}.diagnostic .section{margin:20px 0}
@media(max-width:760px){.report-strip{grid-template-columns:1fr 1fr}.report-stat{border-bottom:1px solid var(--grid);padding:13px 10px 12px 0}.ledger-summary{grid-template-columns:1fr;gap:16px}.item-body .meta-grid{grid-template-columns:1fr;gap:2px}.meta-grid dd{margin-bottom:6px}.tier.regenerable,.tier.manual,.tier.protected{padding-left:12px}.compact-group summary{flex-wrap:wrap}.compact-group-title{min-width:140px}.compact-group-total{flex:0 0 76px}}
"""


TEMPLATE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Codex 文件清理检查</title>
<style>__CSS__
/* Child skill additions: same tokens and chart grammar, Codex-only content. */
__CUSTOM_CSS__</style>
</head>
<body>
<main class="page">
<header class="masthead">
  <div class="eyebrow">CODEX STORAGE CLEANUP · CROSS-USER / CROSS-PLATFORM</div>
  <h1>优先清旧构建，保留最新一份和下载缓存</h1>
  <p>扫描时核对源码和构建配置，每项目保留最新一份，将其余可重建的完整编译目录列为建议删除。Cargo 下载缓存、依赖环境和插件包保留，避免反复下载。下面给出拟删路径、保留路径和重建方式。</p>
</header>
<div id="app"></div>
</main>
<script>
const DATA=__DATA__;
const ACTION_CONFIG=window.__ACTION_CONFIG__||{enabled:false};
const NS='http://www.w3.org/2000/svg',INK='#22211F',MUTED='#8F8E86',FAINT='#C0BFB7',GRID='rgba(31,30,28,.16)',SAFE='#43593B',BAD='#F5572F';
const esc=s=>String(s==null?'':s).replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]));
const bytes=v=>{if(typeof v==='number')return Number.isFinite(v)?v:0;const m=String(v==null?'':v).replace(/,/g,'').match(/([-+]?(?:\d+(?:\.\d*)?|\.\d+))\s*(B|KB|MB|GB|TB)?/i);if(!m)return 0;return Number(m[1])*({B:1,KB:1e3,MB:1e6,GB:1e9,TB:1e12}[String(m[2]||'GB').toUpperCase()]||1e9)};
const fmtBytes=v=>{let n=bytes(v);for(const unit of ['B','KB','MB','GB','TB']){if(n<1000||unit==='TB')return unit==='B'?Math.round(n)+' B':unit==='KB'?Math.round(n)+' KB':n.toFixed(2)+' '+unit;n/=1000}return n.toFixed(2)+' TB'};
const fmtMaybe=v=>v==null||v===''?'未记录':fmtBytes(v);
const fmt=v=>bytes(v)>0?fmtBytes(v):'0 B';
const svgEl=(p,t,a={})=>{const x=document.createElementNS(NS,t);for(const k in a)x.setAttribute(k,a[k]);p.appendChild(x);return x};
const svgText=(p,a,s)=>{const x=svgEl(p,'text',a);x.textContent=s;return x};
const tip=(node,s)=>{const t=document.createElementNS(NS,'title');t.textContent=s;node.appendChild(t)};
const reveal=node=>{node.classList.add('reveal','motion-loaded');return node};
const encodePaths=paths=>btoa(unescape(encodeURIComponent(JSON.stringify(paths||[]))));
const actionButton=(label,mode,paths,danger=false)=>'<button class="action-btn'+(danger?' danger':'')+'" data-action="'+mode+'" data-paths="'+encodePaths(paths)+'">'+label+'</button>';
function drawCandidateGauge(svg){
  const s=DATA.summary||{},total=Math.max(bytes(s.codex_bytes),1),candidate=bytes(s.candidate_bytes),pct=Math.min(100,candidate/total*100),cx=190,cy=158,R=103,A0=-195,SW=210;
  svg.setAttribute('viewBox','0 0 380 300');
  [0,25,50,75,100].forEach(m=>{const a=A0+m/100*SW,r=R-19,x=cx+r*Math.cos(a*Math.PI/180),y=cy+r*Math.sin(a*Math.PI/180);svgText(svg,{x,y:y+3,'text-anchor':'middle','font-size':9,'font-weight':600,fill:MUTED},m+'%')});
  svgText(svg,{x:cx,y:cy-8,'text-anchor':'middle','font-size':27,'font-weight':800,fill:INK},pct.toFixed(1)+'%');
  svgText(svg,{x:cx,y:cy+14,'text-anchor':'middle','font-size':13,'font-weight':700,fill:INK},'建议清理');
  for(let k=0;k<100;k++){const a=A0+k/100*SW,inked=k<pct,len=inked?13:5,x1=cx+R*Math.cos(a*Math.PI/180),y1=cy+R*Math.sin(a*Math.PI/180),x2=cx+(R+len)*Math.cos(a*Math.PI/180),y2=cy+(R+len)*Math.sin(a*Math.PI/180);reveal(svgEl(svg,'line',{x1,y1,x2,y2,stroke:inked?SAFE:FAINT,'stroke-width':inked?1:.6,opacity:inked?1:.72}))}
  svgText(svg,{x:cx,y:cy+52,'text-anchor':'middle','font-size':12,'font-weight':700,fill:SAFE},fmtBytes(candidate)+' / '+fmtBytes(total));
}
function drawUserLens(svg){
  const users=(DATA.users||[]).filter(u=>bytes(u.codex_bytes)>0||bytes(u.candidate_bytes)>0),max=Math.max(...users.map(u=>Math.max(bytes(u.codex_bytes),bytes(u.candidate_bytes))),1),W=520,H=390;
  svg.setAttribute('viewBox','0 0 '+W+' '+H);
  if(!users.length){svgText(svg,{x:W/2,y:H/2,'text-anchor':'middle','font-size':14,fill:MUTED},'没有找到 Codex 文件');return}
  const left=42,right=477,top=42,row=Math.min(78,(H-88)/Math.max(users.length,1));
  users.slice(0,5).forEach((u,i)=>{const y=top+i*row+24,total=bytes(u.codex_bytes),candidate=bytes(u.candidate_bytes),visualTotal=Math.max(total,candidate),radius=18+30*Math.sqrt(visualTotal/max),x=left+radius+5;svgEl(svg,'line',{x1:left,y1:y+35,x2:right,y2:y+35,stroke:GRID,'stroke-width':1});const c=reveal(svgEl(svg,'circle',{cx:x,cy:y,r:Math.min(radius,47),fill:'none',stroke:INK,'stroke-width':1.2}));tip(c,u.user+' · '+fmtBytes(total||candidate));svgText(svg,{x:x,y:y+4,'text-anchor':'middle','font-size':11,'font-weight':800,fill:INK},u.user);svgText(svg,{x:left,y:y+59,'font-size':11,'font-weight':700,fill:INK},u.user);svgText(svg,{x:left+72,y:y+59,'font-size':10,fill:MUTED},fmtBytes(total||candidate)+' · 建议清理 '+fmtBytes(candidate));const barWidth=Math.max((candidate/max)*340,3);reveal(svgEl(svg,'rect',{x:left+72,y:y+66,width:barWidth,height:7,rx:4,fill:SAFE}))});
}
function drawTimeline(svg){
  const data=DATA.timeline||[],W=520,H=390;svg.setAttribute('viewBox','0 0 '+W+' '+H);
  if(!data.length){svgText(svg,{x:W/2,y:H/2,'text-anchor':'middle','font-size':14,fill:MUTED},'没有可用的修改时间');return}
  const max=Math.max(...data.map(d=>bytes(d.size_bytes)),1),left=46,right=478,base=250,step=data.length===1?0:(right-left)/(data.length-1);
  svgEl(svg,'line',{x1:left,y1:base,x2:right,y2:base,stroke:INK,'stroke-width':1.2});
  data.forEach((d,i)=>{const x=data.length===1?262:left+i*step,size=bytes(d.size_bytes),h=26+142*(size/max),bar=reveal(svgEl(svg,'rect',{x:x-10,y:base-h,width:20,height:h,rx:10,fill:i%2?MUTED:INK}));tip(bar,d.date+' · '+fmtBytes(size));svgText(svg,{x,y:base+22,'text-anchor':'middle','font-size':9,fill:MUTED},String(d.date).slice(5));svgText(svg,{x,y:base-h-10,'text-anchor':'middle','font-size':10,'font-weight':700,fill:INK},fmtBytes(size))});
  svgText(svg,{x:left,y:44,'font-size':12,'font-weight':700,fill:INK},'按文件夹最近修改时间统计');
}
function drawPaths(svg){
  const data=(DATA.top_paths||[]).slice(0,9),W=520,H=390;svg.setAttribute('viewBox','0 0 '+W+' '+H);
  if(!data.length){svgText(svg,{x:W/2,y:H/2,'text-anchor':'middle','font-size':14,fill:MUTED},'没有找到可以展示的文件夹');return}
  const max=Math.max(...data.map(d=>bytes(d.size_bytes)),1),x0=190,x1=460,row=Math.min(35,(H-70)/data.length);
  data.forEach((d,i)=>{const y=58+i*row,size=bytes(d.size_bytes),width=Math.max(4,size/max*(x1-x0)),color=d.tier==='regenerable'?SAFE:d.tier==='manual'?BAD:MUTED;svgText(svg,{x:4,y:y+5,'font-size':11,'font-weight':700,fill:INK},String(d.name).slice(0,22));const bar=reveal(svgEl(svg,'rect',{x:x0,y:y-9,width,height:18,rx:9,fill:'#C0BFB7'}));const fill=reveal(svgEl(svg,'rect',{x:x0,y:y-9,width,height:18,rx:9,fill:color}));tip(fill,d.path+' · '+fmtBytes(size));svgText(svg,{x:x1+10,y:y+5,'font-size':10,'font-weight':700,fill:color},fmtBytes(size))});
}
function renderCard(title,sub,chart,tag){return '<article class="card square"><div class="eyebrow">'+tag+'</div><h2>'+title+'</h2><p class="sub">'+sub+'</p>'+chart+'</article>'}
function renderHero(){
  const s=DATA.summary||{},scope=DATA.scope||{},p=DATA.platform||{},u=((DATA.large_file_discovery||{}).usage_summary)||{};
  const total=u.codex_logical_bytes!=null?u.codex_logical_bytes:s.codex_bytes;
  const locations=(u.locations||[]).slice(0,4).map(row=>esc(row.label||row.path||'未记录位置')+' '+fmtBytes(row.logical_bytes)).join(' · ')||'位置拆分暂未记录';
  return '<section class="hero cleanup-hero"><div class="hero-main"><div class="hero-label">Codex 总占用</div><div class="hero-number"><span class="accent">'+fmtMaybe(total)+'</span></div><div class="hero-meta">按位置：'+locations+'</div></div><div class="hero-side"><strong>'+esc(p.name||'当前平台')+'</strong><div class="rule"></div><p>'+esc(DATA.generated_at||'检查时间未记录')+' · '+esc(p.current_user||'当前账号未记录')+'</p><p>本页只做检查和说明，移动或删除需要单独授权。</p></div></section><div class="report-strip"><div class="report-stat"><b>'+fmtMaybe(total)+'</b><span>Codex 总占用</span></div><div class="report-stat"><b>'+fmtMaybe(DATA.free_bytes)+'</b><span>可用空间</span></div><div class="report-stat green"><b>'+fmtMaybe(s.old_build_bytes)+'</b><span>旧构建评估量</span></div><div class="report-stat orange"><b>'+fmtMaybe(s.manual_bytes)+'</b><span>还需确认的内容</span></div></div>';
}
function renderCharts(){
  return '<section class="chart-grid">'+renderCard('建议清理的文件有多少？','F11 · 只计算已经找到的 Codex 文件夹和待处理文件','<svg id="candidate-gauge" class="chart-square" data-chart="candidate-gauge" aria-label="建议清理的文件占 Codex 文件比例"></svg>','SCOPE / RATIO')+renderCard('哪个用户占用最多？','每个圆环代表一个找到 Codex 文件的用户','<svg id="user-lens" class="chart-lens" data-chart="user-lens" aria-label="各用户的 Codex 文件占用"></svg>','USERS / LENS')+renderCard('这些文件是什么时候留下的？','F2 · 按文件夹最近修改时间统计','<svg id="codex-timeline" class="chart-history" data-chart="codex-timeline" aria-label="Codex 文件时间线"></svg>','AGE / TIMELINE')+renderCard('具体是哪些文件夹？','G10 · 条形只代表建议清理的部分，不代表整个工作区','<svg id="codex-paths" class="chart-wide" data-chart="codex-paths" aria-label="建议删除的旧构建产物夹"></svg>','PATHS / LEDGER')+'</section>';
}
function renderUsage(){
  const d=DATA.large_file_discovery||{},u=d.usage_summary||{},locations=u.locations||[],projects=u.projects||[];
  const locationRows=locations.map(row=>'<tr><td>'+esc(row.label||row.path||'未记录位置')+'</td><td class="path">'+esc(row.path||'未记录路径')+'</td><td class="num">'+fmtBytes(row.logical_bytes)+'</td></tr>').join('')||'<tr><td colspan="3">位置拆分未记录</td></tr>';
  const projectRows=projects.map(row=>'<tr><td>'+esc(row.project_key||'项目暂未标注')+'</td><td class="num">'+fmtBytes(row.logical_bytes)+'</td></tr>').join('')||'<tr><td colspan="2">项目拆分未记录</td></tr>';
  const retainedRows=(d.top_retained_contents||[]).map(row=>'<tr><td class="path">'+esc(row.path||'未记录')+'</td><td class="num">'+fmtBytes(row.logical_bytes)+'<br><span class="status-muted">分配 '+fmtBytes(row.allocated_bytes)+'</span></td><td>'+esc(row.retained_reason||'保留原因未记录')+' '+esc(row.remaining_condition||'')+(row.policy_candidates_still_present?.length?'<br><span class="status-warn">当前仍有 '+esc(row.policy_candidates_still_present.length)+' 项默认策略候选，需结合执行结果确认</span>':'')+'</td></tr>').join('')||'<tr><td colspan="3">没有可计量的保留内容</td></tr>';
  const missing=u.codex_without_project_logical_bytes?'<p class="scope-note">其中 '+fmtBytes(u.codex_without_project_logical_bytes)+' 已确认属于 Codex，但暂时没有对应项目名称。</p>':'';
  return '<section class="section"><div class="section-head"><h2>Codex 占用明细</h2><div class="source">USAGE / PLAIN SUMMARY</div></div><div class="table-wrap"><table class="table"><thead><tr><th>位置</th><th>路径</th><th>Codex 占用</th></tr></thead><tbody>'+locationRows+'</tbody></table></div>'+missing+'<h3>按项目</h3><div class="table-wrap"><table class="table"><thead><tr><th>项目</th><th>Codex 占用</th></tr></thead><tbody>'+projectRows+'</tbody></table></div><h3>最大的三项保留内容</h3><p class="scope-note">按不重叠目录或任务分组，文件身份去重；逻辑大小与分配大小分开显示。</p><div class="table-wrap"><table class="table"><thead><tr><th>位置 / 任务</th><th>逻辑 / 分配</th><th>保留原因与尚需满足的条件</th></tr></thead><tbody>'+retainedRows+'</tbody></table></div><details class="diagnostic"><summary>展开详细诊断</summary><p class="scope-note">文件数、目录数、来源证据、阶段状态和原始扫描信息只放在这里，便于追查问题，不作为每日摘要。</p>'+renderDiscovery()+'</details></section>';
}
function renderScope(){
  const users=DATA.users||[];if(!users.length)return '<section class="section"><div class="empty-state">没有发现可读取的本地用户目录。</div></section>';
  const rows=users.map(u=>{const roots=(u.codex_roots||[]).map(r=>'<span class="root-chip" title="'+esc(r.path)+'">'+esc(r.label||r.kind)+' · '+esc(r.size||'—')+'</span>').join('');const status=u.status==='已读取'?'<span class="status-ok">已读取</span>':u.status==='部分受限'?'<span class="status-warn">部分受限</span>':'<span class="status-muted">不可读取</span>';return '<tr><td><span class="user-pill">'+esc(u.user)+'</span><span class="user-home">'+esc(u.home)+'</span></td><td>'+esc(u.platform||'—')+'</td><td>'+status+'</td><td>'+((u.codex_roots||[]).length?roots:'<span class="status-muted">没有找到 Codex 文件夹</span>')+'</td><td class="num">'+esc(u.codex_size||'0 B')+'</td><td class="num">'+esc(u.candidate_size||'0 B')+'<br><span class="status-muted">'+(u.candidate_count||0)+' 项</span></td></tr>'}).join('');
  return '<section class="section"><div class="section-head"><h2>检查了哪些用户和文件夹？</h2><div class="source">DISCOVERY / PROVENANCE</div></div><p class="scope-note">只检查当前账号的 Codex 固定目录，以及 Codex 状态/会话明确关联的具体项目和登记 worktree。Documents 只用于有限入口发现；不会递归扫描整个 home、Documents 或 Library。iCloud、外置卷和其他账号不在范围内。</p><div class="table-wrap"><table class="table scope-table"><thead><tr><th>用户 / 文件夹</th><th>平台</th><th>检查结果</th><th>找到的 Codex 文件夹</th><th>Codex 占用</th><th>建议清理</th></tr></thead><tbody>'+rows+'</tbody></table></div></section>';
}
function itemActions(it){
  const out=[];const opens=it.open_paths||[];const trash=it.trash_paths||[];
  if(opens.length)out.push(actionButton('打开位置','open',opens));
  if(trash.length)out.push(actionButton('移到废纸篓/回收站','trash',trash));
  if(!ACTION_CONFIG.enabled&&out.length)out.push('<span class="action-note">启动本地服务后启用</span>');
  return out.length?'<div class="action-row">'+out.join('')+'</div>':'';
}
function renderItem(it,tier,maxSize){
  const size=bytes(it.size_bytes),pct=Math.min(100,size/Math.max(maxSize,1)*100),tag=tier==='regenerable'?'<span class="ledger-tag green">建议清理</span>':tier==='manual'?'<span class="ledger-tag orange">先看一下</span>':'<span class="ledger-tag">建议保留</span>';
  const meter='<span class="item-meter" title="相对本组最大占用：'+pct.toFixed(1)+'%"><span class="item-meter-fill" style="width:'+pct.toFixed(1)+'%"></span></span>';
  const actionLabel={'direct-delete':'默认直接删除（可再生成）','backup-then-delete':'先备份到 T1，校验后删除独立旧成果','migrate-to-t1':'移动到 T1，原路径软链接可访问','retain':'保留'}[it.default_action]||'需单独核实';
  const meta='<dl class="meta-grid"><dt>文件位置</dt><dd class="path">'+esc(it.path)+'</dd><dt>默认处置</dt><dd>'+esc(actionLabel)+'</dd><dt>为什么算作 Codex 文件</dt><dd>'+esc(it.provenance)+'</dd><dt>为什么现在列出来</dt><dd>'+esc(it.rebuild_basis||it.reason)+'</dd><dt>是否正在使用</dt><dd>'+esc(it.activity||'没有找到相关信息')+'</dd><dt>项目状态</dt><dd>'+esc(it.git_state||'不适用')+'</dd><dt>保留哪一份</dt><dd>'+esc(it.retained_path||'不适用')+'</dd><dt>如何重建</dt><dd>'+esc(it.rebuild_command||'见恢复说明')+'</dd><dt>流量与时间成本</dt><dd>'+esc(it.network_cost||'未核实')+'；'+esc(it.rebuild_time||'未测量')+'</dd><dt>怎么恢复</dt><dd>'+esc(it.recovery||'请先确认')+'</dd><dt>建议怎么处理</dt><dd>'+esc(it.recommendation||'保留')+'</dd></dl>';
  const source=it.source_root?'<p><span class="label">源码保留在</span> '+esc(it.source_root)+' · '+esc(it.source_revision||'未提交仓库')+'</p>':'';
  const extra=source+(it.file_count!=null?'<p><span class="label">归档文件数量</span> '+esc(it.file_count)+(it.file_count_note?' · '+esc(it.file_count_note):'')+'</p>':'');
  return '<details class="item"><summary><span class="item-name">'+esc(it.name)+' '+tag+'<span class="item-explainer">'+esc(it.artifact_type)+' · '+esc(it.user)+' · 最后修改于 '+esc(it.modified_at||'未读取')+'</span></span>'+meter+'<span class="item-size">'+esc(it.size||fmtBytes(size))+'</span></summary><div class="item-body">'+meta+extra+itemActions(it)+'</div></details>';
}
const COMPACT_START=100*1000*1000;
const COMPACT_MIN_VISIBLE=5;
const compactThresholdLabel=threshold=>fmtBytes(threshold).replace(/\.0 (?=[A-Z])/, ' ');
function renderCompactGroup(items,tier,maxSize,upperThreshold,groupLabel='',groupSub=''){
  const ordered=items.slice().sort((a,b)=>bytes(b.size_bytes)-bytes(a.size_bytes)),nextThreshold=upperThreshold/10;
  const shown=ordered.filter(item=>bytes(item.size_bytes)>=nextThreshold),smaller=ordered.filter(item=>bytes(item.size_bytes)<nextThreshold);
  const shownHtml=shown.map(item=>renderItem(item,tier,maxSize)).join('');
  const smallerHtml=smaller.length?(nextThreshold>=1000?renderCompactGroup(smaller,tier,maxSize,nextThreshold):smaller.map(item=>renderItem(item,tier,maxSize)).join('')):'';
  const total=ordered.reduce((sum,item)=>sum+bytes(item.size_bytes),0);
  const pct=Math.min(100,total/Math.max(maxSize,1)*100),meter='<span class="item-meter compact-meter" title="其他合计 '+fmtBytes(total)+'，相对本组最大项目 '+pct.toFixed(1)+'%"><span class="item-meter-fill" style="width:'+pct.toFixed(1)+'%"></span></span>';
  return '<details class="compact-group"><summary><span class="compact-group-title">其他 · '+(groupLabel||'小于 '+compactThresholdLabel(upperThreshold))+'<span class="compact-group-sub">'+(groupSub||'展开后继续按 10 倍大小查看')+'</span></span>'+meter+'<span class="compact-group-total item-size">'+fmtBytes(total)+' · '+ordered.length+' 项</span></summary><div class="compact-group-body">'+shownHtml+smallerHtml+'</div></details>';
}
function renderCompactItems(ordered,tier,maxSize){
  if(ordered.length<=COMPACT_MIN_VISIBLE)return ordered.map(item=>renderItem(item,tier,maxSize)).join('');
  const shown=ordered.filter(item=>bytes(item.size_bytes)>=COMPACT_START),smaller=ordered.filter(item=>bytes(item.size_bytes)<COMPACT_START);
  if(shown.length<COMPACT_MIN_VISIBLE){
    const top=ordered.slice(0,COMPACT_MIN_VISIBLE),rest=ordered.slice(COMPACT_MIN_VISIBLE);
    return top.map(item=>renderItem(item,tier,maxSize)).join('')+renderCompactGroup(rest,tier,maxSize,COMPACT_START,'其余项目','前 5 项已单独显示，展开查看剩余项目');
  }
  return shown.map(item=>renderItem(item,tier,maxSize)).join('')+(smaller.length?renderCompactGroup(smaller,tier,maxSize,COMPACT_START):'');
}
function renderTier(title,kicker,intro,items,tier){
  if(!items.length)return '';
  const ordered=items.slice().sort((a,b)=>bytes(b.size_bytes)-bytes(a.size_bytes)),max=Math.max(...ordered.map(item=>bytes(item.size_bytes)),1),total=ordered.reduce((sum,item)=>sum+bytes(item.size_bytes),0);
  return '<div class="tier '+tier+'"><div class="tier-head"><div><div class="tier-kicker '+(tier==='regenerable'?'green':tier==='manual'?'orange':'')+'">'+kicker+'</div><h3>'+title+' · '+ordered.length+' 项</h3><p class="tier-intro">'+intro+'</p></div><div class="tier-head-meta"><div class="tier-total">'+fmtBytes(total)+'</div></div></div>'+renderCompactItems(ordered,tier,max)+'</div>';
}
function renderDiscovery(){
  const d=DATA.large_file_discovery||{};if(!d.enabled)return '';const directoryPresent=Array.isArray(d.directory_summary);
  const c=d.coverage||{},t=d.totals||{},files=d.large_files||[],vms=(d.virtual_machines&&d.virtual_machines.items)||[],runs=d.test_runs||[],dups=d.duplicates||{};
  const rows=files.map(it=>'<tr><td class="path">'+esc(it.path)+'</td><td class="num">'+esc(it.logical_size||'—')+'</td><td class="num">'+esc(it.allocated_size||'—')+'</td><td>'+esc(it.kind||'未知')+'</td><td>'+esc(it.project_key||'归属不明')+' · '+esc(it.project_confidence||'未检查')+'</td><td>'+esc(it.source_evidence||'来源未核实')+'</td></tr>').join('')||'<tr><td colspan="6">没有达到当前阈值的大项</td></tr>';
  const directoryRows=(directoryPresent?d.directory_summary:[]).map(it=>'<tr><td class="path">'+esc(it.path)+'</td><td class="num">'+esc(it.file_count??'未记录')+'</td><td class="num">'+esc(it.logical_size||'—')+'</td><td class="num">'+esc(it.allocated_size||'—')+'</td><td>'+esc(it.source_status||'未记录')+' · '+esc(it.origin_state||'未记录')+' · 关联 '+esc(it.association_status||'未记录')+' · 证据 '+esc(it.evidence_status||'未记录')+'</td><td>'+esc(it.purpose||'用途待确认')+'；覆盖 '+esc(it.coverage_status||'未记录')+'；处置 '+esc(it.disposition_class||'暂不处理')+'（计划 '+esc(it.planned_disposition_class||'暂不处理')+'）；活动 '+esc(it.activity_status||'未检查')+'；可释放 '+esc(it.reclaimable_size||'未知')+'；建议 '+esc(it.suggested_disposition||'暂不处理')+'；证据 '+esc(it.source_evidence||'缺少可读取证据')+'；缺少证据 '+esc(it.evidence_error||'无')+'；保留 '+esc(it.retention_note||'待确认')+'；恢复 '+esc(it.recovery_cost||'待确认')+'</td></tr>').join('')||'<tr><td colspan="6">没有目录级统计；旧报告未记录</td></tr>';
  const directoryMeta=d.directory_summary_meta||{};
  const runtimeRows=(d.runtime_mappings||[]).map(it=>'<tr><td>'+esc(it.id||'未记录')+'</td><td class="path">'+esc(it.path||'未记录')+'</td><td>'+esc(it.source_status||'未记录')+' · 关联 '+esc(it.association_status||'未记录')+' · 证据 '+esc(it.evidence_status||'未记录')+'</td><td>'+esc(it.origin_state||'未记录')+'</td><td>'+esc(it.purpose||'用途待确认')+'</td><td>'+esc(it.activity_status||'未检查')+'；处置 '+esc(it.disposition_class||'暂不处理')+'（计划 '+esc(it.planned_disposition_class||'暂不处理')+'）；建议 '+esc(it.suggested_disposition||'暂不处理')+'；证据 '+esc(it.evidence||'缺少可读取证据')+'；缺少证据 '+esc(it.evidence_error||'无')+'；保留 '+esc(it.retention_note||'待确认')+'；恢复 '+esc(it.recovery_cost||'待确认')+'</td></tr>').join('')||'<tr><td colspan="6">旧报告未记录工程外运行数据映射</td></tr>';
  const smallRows=(d.small_file_summary||[]).map(it=>'<tr><td>'+esc(it.kind||'未知')+'</td><td class="num">'+esc(it.count||0)+'</td><td class="num">'+esc(it.logical_size||'—')+'</td><td class="num">'+esc(it.allocated_size||'—')+'</td><td>'+esc((it.paths||[]).join('；')||'仅保留汇总样本')+'</td></tr>').join('')||'<tr><td colspan="5">没有小项汇总</td></tr>';
  const vmRows=vms.map(it=>'<tr><td class="path">'+esc(it.path)+'</td><td class="num">'+esc(it.logical_size||'—')+' / '+esc(it.allocated_size||'—')+'</td><td>'+esc(it.open_status||'未检查')+'；'+esc(it.process_status||'未检查')+'</td><td>'+esc(it.mounted||'未检查')+'</td><td>'+esc((it.dependency_paths||[]).length)+' 已解析；'+esc((it.missing_dependency_paths||[]).length)+' 缺失；'+esc((it.external_dependency_paths||[]).length)+' 越界</td></tr>').join('')||'<tr><td colspan="5">未发现可识别的虚拟机包或磁盘大项</td></tr>';
  const runRows=runs.map(it=>'<tr><td class="path">'+esc(it.path)+'</td><td>'+esc(it.project_key||'归属不明')+' · '+esc(it.project_confidence||'未检查')+'</td><td>'+esc(it.completion_status||'未检查')+'</td><td>'+esc(it.dependency_count||0)+'；被 '+esc((it.referenced_by||[]).length)+' 个批次引用</td><td>'+esc((it.references||[]).join('；')||'未发现显式引用')+'</td></tr>').join('')||'<tr><td colspan="5">未发现带有可解析状态或 manifest 的测试运行</td></tr>';
  const duplicateCount=dups.groups_count||((dups.groups||[]).length),duplicateNotice=duplicateCount>(dups.groups||[]).length?'<p class="scope-note">已确认重复共 '+esc(duplicateCount)+' 组；当前报告展示最大/代表性 '+esc((dups.groups||[]).length)+' 组。完整逐组证据保存在 '+esc(dups.full_evidence_path||'扫描工作目录')+'，未把其余组静默计入清理建议。</p>':'';
  const duplicateRows=(dups.groups||[]).map(it=>'<tr><td class="num">'+esc(it.extra_logical_size||'—')+'</td><td>'+esc(it.copy_count||0)+'</td><td class="path">'+esc((it.paths||[]).join('；'))+'</td><td>'+esc(it.evidence||'内容证据未检查')+'</td></tr>').join('')||'<tr><td colspan="4">没有已确认内容重复</td></tr>';
  const deferredRows=(dups.deferred_groups||[]).concat(dups.unverified_same_size_groups||[]).map(it=>'<tr><td class="num">'+esc(it.extra_logical_size||it.logical_size||'—')+'</td><td class="path">'+esc((it.paths||[]).join('；'))+'</td><td>'+esc(it.deferred_reason||it.reason||'尚未完成稳定校验')+'</td></tr>').join('')||'<tr><td colspan="3">没有延后或未验证的重复候选</td></tr>';
  const gaps=[];(c.errors||[]).forEach(x=>gaps.push((x.path||'未知路径')+' · '+(x.reason||'扫描失败')+' · '+(x.phase||'未分类')));(c.skipped_mounts||[]).forEach(x=>gaps.push((x.path||'未知挂载')+' · '+(x.reason||'跨卷跳过')));if(c.interrupted)gaps.push('扫描被中断，结果为部分覆盖');
  const stageHtml='<p class="scope-note">分阶段状态：'+esc(c.stages?Object.entries(c.stages).map(([key,value])=>key+'='+value).join('；'):'未检查（旧台账）')+'。原始事件 '+esc(c.raw_event_count??'未检查')+'；唯一诊断 '+esc(c.unique_diagnostic_count??'未检查')+'；受影响路径 '+esc(c.unique_affected_path_count??'未检查')+'。</p>';
  const diagnosticRows=items=>items.map(it=>'<details><summary>'+esc(it.severity+' · '+it.phase+' · '+it.path+' · '+it.code+' × '+it.occurrences)+'</summary><pre>'+esc(JSON.stringify(it.sources,null,2))+'</pre></details>').join('');
  const diagnosticsHtml='<h3>真实检查缺口 '+esc(c.gap_count??'未检查')+'</h3>'+diagnosticRows((c.diagnostics||[]).filter(it=>it.severity==='error'))+'<h3>历史、外部引用与格式恢复提示</h3>'+diagnosticRows((c.diagnostics||[]).filter(it=>it.severity!=='error'));
  const exclusionsHtml='<details><summary>跨卷跳过 '+esc((c.skipped_mounts||[]).length)+' 项；符号链接 '+esc((c.symlinks||[]).length)+' 项（不跟随）</summary><pre>'+esc(JSON.stringify({mounts:c.skipped_mounts||[],links:c.symlinks||[]},null,2))+'</pre></details>'+(c.interrupted?'<p class="scope-note">扫描被中断；不能宣称验收完成。</p>':'');
  const candidatesHtml='<details><summary>非运行元数据候选 '+esc((d.metadata_candidates||[]).length)+' 项（配置、夹具或未识别）</summary>'+(d.metadata_candidates||[]).map(it=>'<details><summary>'+esc(it.path+' · '+it.classification)+'</summary><pre>'+esc(JSON.stringify(it,null,2))+'</pre></details>').join('')+'</details><details><summary>来源引用 '+esc((d.source_references||[]).length)+' 项</summary><pre>'+esc(JSON.stringify(d.source_references||[],null,2))+'</pre></details>';
  const timingHtml='<p class="scope-note">数据采集总耗时（不含报告构建）：'+esc(DATA.scan_elapsed_seconds??'未检查')+' 秒；阶段耗时：'+esc(c.phase_timings?Object.entries(c.phase_timings).map(([key,value])=>key+'='+value+'s').join('；'):'未检查')+'。日常模式未读取文件头 '+esc(c.signature_unchecked_count??'未检查')+' 项；完整内容校验是否执行：'+esc(c.duplicate_hash_requested?'是':'否')+'。</p>';
  const purpose=d.purpose_analysis||{};
  const purposeHtml='<h3>进一步用途分析</h3><p class="scope-note">'+esc(purpose.status||'未检查（旧报告）')+'；目标 '+esc(purpose.target_count??'未检查')+' 项；耗时 '+esc(purpose.elapsed_seconds??'未检查')+' 秒；阶段 '+esc(purpose.phase_status?Object.entries(purpose.phase_status).map(([key,value])=>key+'='+value).join('；'):'未检查')+'；预算 '+esc(purpose.budget_exhausted?'已用尽':'未用尽')+'。用途判断不会消除覆盖缺口或产生删除权限。</p>'+(purpose.failure?'<p class="scope-note">用途分析缺口：'+esc(purpose.failure)+'</p>':'')+(purpose.items||[]).map(it=>'<details><summary>'+esc(it.path+' · '+it.purpose+' · 建议'+it.recommendation)+'</summary><p>'+esc((it.remaining_questions||[]).join('；'))+'</p><pre>'+esc(JSON.stringify(it,null,2))+'</pre></details>').join('');
  const runtimeHtml='<h3>工程外运行数据映射</h3><p class="scope-note">映射使用固定应用标识和路径；历史缺失不计入当前占用，活动状态未检查不表示闲置，T1 线索也不表示迁移已验证。</p><div class="table-wrap"><table class="table"><thead><tr><th>映射</th><th>路径</th><th>来源状态</th><th>归属状态</th><th>用途</th><th>活动 / 建议</th></tr></thead><tbody>'+runtimeRows+'</tbody></table></div>';
  const gapHtml=timingHtml+stageHtml+purposeHtml+runtimeHtml+(c.diagnostics?diagnosticsHtml:(gaps.length?'<ul class="list">'+gaps.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul>':'<p class="scope-note">未记录缺口；不代表删除授权。</p>'))+candidatesHtml+exclusionsHtml;
  return '<section class="section"><div class="section-head"><h2>主目录全面发现：占用、归属、重复与虚拟机</h2><div class="source">DISCOVERY ONLY · NO ACTIONS</div></div><p class="scope-note">范围：'+esc(d.scope||'当前用户主目录')+'；扫描根：'+esc((d.scan_roots||[]).join('；'))+'。逻辑大小与文件系统分配大小分开显示，父子目录和硬链接不重复计入。内容重复只表示字节证据，不代表可删除，也不计入物理可释放空间。所有新增分析项的删除路径为空。</p><div class="report-strip"><div class="report-stat"><b>'+esc(t.discovered_logical_size||'—')+'</b><span>本机发现 · 逻辑字节</span></div><div class="report-stat"><b>'+esc(t.discovered_allocated_size||'—')+'</b><span>本机发现 · 分配字节</span></div><div class="report-stat"><b>'+esc(t.codex_logical_size||'—')+'</b><span>已确认 Codex 来源 · 逻辑字节</span></div><div class="report-stat orange"><b>'+esc((dups.logical_duplicate_size)||'—')+'</b><span>稳定内容重复 · 多余逻辑字节</span></div></div><p class="scope-note">库存 '+esc(c.all_file_inventory_count||0)+' 个文件实体，展示 '+esc(files.length)+' 个达到 '+esc(fmtBytes(c.min_large_bytes||0))+' 的大项；遍历耗时 '+esc(c.elapsed_seconds||'未读取')+' 秒。归属不明：'+esc(t.unattributed_logical_size||'—')+'；实际可释放量：'+esc(t.physical_reclaimable||'未知')+'。</p><h3>目录级统计（累计小文件也展示）</h3><p class="scope-note">目录统计共 '+esc(directoryMeta.total_count??'未记录')+' 项；当前展示 '+esc(directoryPresent?d.directory_summary.length:'未记录')+' 项，未展开 '+esc(directoryMeta.omitted_count??'未记录')+' 项。每项包含来源状态、用途和处置建议；这些建议不产生删除权限。</p><div class="table-wrap"><table class="table"><thead><tr><th>目录</th><th>文件</th><th>逻辑</th><th>分配</th><th>来源状态</th><th>用途 / 建议</th></tr></thead><tbody>'+directoryRows+'</tbody></table></div><h3>大项（全量展示）</h3><div class="table-wrap"><table class="table"><thead><tr><th>路径</th><th>逻辑</th><th>分配</th><th>类型提示</th><th>项目归属</th><th>来源/证据</th></tr></thead><tbody>'+rows+'</tbody></table></div><h3>小项汇总（按类型，可展开路径样本）</h3><div class="table-wrap"><table class="table"><thead><tr><th>类型</th><th>文件实体</th><th>逻辑</th><th>分配</th><th>样本/说明</th></tr></thead><tbody>'+smallRows+'</tbody></table></div><h3>虚拟机与容器磁盘</h3><div class="table-wrap"><table class="table"><thead><tr><th>路径/包</th><th>逻辑 / 分配</th><th>句柄/进程</th><th>挂载</th><th>依赖</th></tr></thead><tbody>'+vmRows+'</tbody></table></div><h3>已确认内容重复</h3>'+duplicateNotice+'<div class="table-wrap"><table class="table"><thead><tr><th>多余逻辑</th><th>实体副本</th><th>路径</th><th>证据</th></tr></thead><tbody>'+duplicateRows+'</tbody></table></div><h3>疑似重复、延后和失败校验</h3><div class="table-wrap"><table class="table"><thead><tr><th>大小</th><th>路径</th><th>原因</th></tr></thead><tbody>'+deferredRows+'</tbody></table></div><h3>测试运行与跨目录引用</h3><div class="table-wrap"><table class="table"><thead><tr><th>运行目录</th><th>项目归属</th><th>完成状态</th><th>依赖关系</th><th>引用</th></tr></thead><tbody>'+runRows+'</tbody></table></div><h3>扫描覆盖缺口</h3>'+gapHtml+'</section>';
}
function renderDecision(){
  const green=DATA.green||[],old=green.filter(it=>it.review_priority==='delete-old-build'),secondary=green.filter(it=>it.review_priority!=='delete-old-build');
  const summary=DATA.summary||{};
  const archive=fmtBytes(summary.archive_backup_delete_bytes),backup=fmtBytes(summary.backup_then_delete_bytes),worktrees=summary.finalized_worktree_count||0,idle=summary.idle_worktree_count||0;
  return '<section class="section"><div class="section-head"><h2>默认清理策略</h2></div><div class="ledger-summary"><div><h2>旧构建和可再生缓存直接删除</h2><p>拟删目录已核对源码入口、构建配置和产物结构；每个项目保留最新完整可用的一份。缓存和旧构建不做备份，因为可以重新生成。</p></div><div><p>备份后删除候选合计：约 '+backup+'，其中超过 7 天归档约 '+archive+'；必须先完成 T1 快照和校验。</p><p>关联组连续超过 168 小时闲置且全部检查通过的 worktree：'+worktrees+' 项（闲置入口 '+idle+' 项）移动到 T1；定稿标记不能覆盖近期或未知状态。校验后删除本机副本，原路径软链接可访问。</p></div></div>'+renderTier('建议直接删除 · 可从源码重建的旧目录','OLD BUILDS','展开查看源码、重建命令和最新保留路径。',old,'regenerable')+renderTier('保留 · 最新构建、依赖和核心数据','KEEP','每项目最新一份及正在使用的目录；源码和下载缓存保留。',DATA.red||[],'protected')+renderTier('默认直接删除 · 可再生缓存和临时文件','SECONDARY','仅处理有真实重建证据、且执行前确认没有打开句柄的目录。',secondary,'regenerable')+renderTier('先备份再删 / T1 迁移 / 用户数据','UNRESOLVED','归档旧文件和有结束证据的独立成果先备份后删；关联组连续超过 168 小时闲置且全部检查通过的 worktree 搬到 T1；定稿标记不能覆盖近期或未知状态；其他用户数据继续保留。',DATA.yellow||[],'manual')+'</section>';
}
function renderIssues(){
  const meta=DATA.ledger_meta||{},issues=meta.issues||[],scope=DATA.scope||{};if(!issues.length&&!((scope.unreadable_homes||[]).length))return '';
  const rows=issues.map(issue=>'<li>'+esc(issue.user||'未知用户')+' · '+esc(issue.path||'')+' · '+esc(issue.reason||'无法读取')+'</li>').join('');const unread=(scope.unreadable_homes||[]).map(home=>'<li>无法完整读取的用户文件夹：'+esc(home)+'</li>').join('');return '<section class="issue-panel"><h2>没有完整读取的地方</h2><p>权限不足或无法完整读取的内容不会被列为可以清理的文件。</p><ul>'+unread+rows+'</ul></section>';
}
function renderFooter(){const p=DATA.platform||{},s=DATA.scope||{};return '<footer class="footer">CODEX STORAGE CLEANUP · '+esc(p.name||'平台未识别')+' · '+esc(DATA.generated_at||'')+' · 已检查 '+(s.user_count||0)+' 个用户 · 找到 '+(s.codex_root_count||0)+' 个 Codex 文件夹 · 只查看，尚未操作</footer>'}
const app=document.getElementById('app');
app.innerHTML=renderHero()+renderCharts()+'<div id="below-fold-sentinel" class="deferred-sentinel" aria-hidden="true"></div>';
const chartFns={'candidate-gauge':drawCandidateGauge,'user-lens':drawUserLens,'codex-timeline':drawTimeline,'codex-paths':drawPaths};
const initCharts=()=>{Object.entries(chartFns).forEach(([id,fn])=>{const node=document.getElementById(id);if(node&&node.dataset.ready!=='1'){fn(node);node.dataset.ready='1'}})};
requestAnimationFrame(()=>requestAnimationFrame(initCharts));
let belowLoaded=false;const loadBelow=()=>{if(belowLoaded)return;belowLoaded=true;const sentinel=document.getElementById('below-fold-sentinel');if(sentinel)sentinel.remove();app.insertAdjacentHTML('beforeend',renderUsage()+'<details class="diagnostic"><summary>展开扫描范围</summary>'+renderScope()+'</details>'+renderDecision()+renderIssues()+renderFooter());app.querySelectorAll('.reveal').forEach(node=>node.classList.add('motion-loaded'))};
const observer='IntersectionObserver' in window?new IntersectionObserver(entries=>{if(entries.some(entry=>entry.isIntersecting)){loadBelow();observer.disconnect()}},{root:null,rootMargin:'360px 0px',threshold:.01}):null;const sentinel=document.getElementById('below-fold-sentinel');if(observer)observer.observe(sentinel);if(window.requestIdleCallback)requestIdleCallback(loadBelow,{timeout:900});else setTimeout(loadBelow,400);
async function performAction(button){const mode=button.dataset.action,paths=JSON.parse(decodeURIComponent(escape(atob(button.dataset.paths)))),label=mode==='trash'?'移到废纸篓/回收站':'打开位置';if(!ACTION_CONFIG.enabled){alert('请通过 Codex 清理页面操作。');return}if(mode==='trash'&&!confirm('确认'+label+'？\n\n'+paths.join('\n')))return;button.disabled=true;try{const result=await fetch(ACTION_CONFIG.endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:ACTION_CONFIG.token,mode,paths})}),body=await result.json();if(!result.ok||!body.ok)throw new Error(body.error||'操作失败');button.textContent=mode==='open'?'已打开':'已移入废纸篓/回收站'}catch(error){button.disabled=false;alert(error.message||'操作失败')}}
document.addEventListener('click',event=>{const action=event.target.closest('.action-btn');if(action){event.stopPropagation();performAction(action)}});
</script>
</body>
</html>
"""


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: build_codex_report.py <data.json> <report.html>")
        return 2
    data_path, report_path = map(Path, sys.argv[1:3])
    data = json.loads(data_path.read_text(encoding="utf-8"))
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    html = TEMPLATE.replace("__CSS__", parent_css()).replace("__CUSTOM_CSS__", CUSTOM_CSS).replace("__DATA__", payload)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(html, encoding="utf-8")
    print(f"Codex 清理报告已生成: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
