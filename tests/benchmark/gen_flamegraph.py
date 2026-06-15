#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Generate a self-contained interactive HTML flame graph from OTLP JSON traces."""

import base64
import json
import sys
from collections import defaultdict


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_spans(path: str) -> list[dict]:
    """Load all spans from an OTLP JSON file."""
    with open(path) as f:
        data = json.load(f)
    spans = []
    for rs in data.get("resourceSpans", []):
        for ss in rs.get("scopeSpans", []):
            for sp in ss.get("spans", []):
                spans.append(sp)
    return spans


def decode_id(b64: str) -> str:
    """Decode base64-encoded trace/span ID to hex string."""
    return base64.b64decode(b64).hex()


def get_attr(attrs: list, key: str) -> str | None:
    """Extract a string value from an OTLP attribute list."""
    for a in attrs:
        if a["key"] == key:
            v = a["value"]
            if "stringValue" in v:
                return v["stringValue"]
            if "boolValue" in v:
                return str(v["boolValue"])
            if "arrayValue" in v:
                vals = v["arrayValue"].get("values", [])
                return ", ".join(x.get("stringValue", "") for x in vals)
    return None


def parse_span(sp: dict) -> dict:
    """Convert a raw OTLP span dict to a simplified internal dict."""
    attrs = sp.get("attributes", [])
    events = sp.get("events", [])
    start_ns = int(sp["startTimeUnixNano"])
    end_ns = int(sp["endTimeUnixNano"])

    important_attrs = {}
    for key in (
        "event",
        "event_type",
        "action",
        "services",
        "executable",
        "path",
        "call",
        "kwargs",
        "juju.dispatch_path",
        "label",
    ):
        val = get_attr(attrs, key)
        if val is not None:
            important_attrs[key] = val

    # Extract the first juju event kind from the span's events[] array.
    juju_event_kind = None
    for ev in events:
        kind = get_attr(ev.get("attributes", []), "kind")
        if kind:
            juju_event_kind = kind
            break

    return {
        "traceId": decode_id(sp["traceId"]),
        "spanId": decode_id(sp["spanId"]),
        "parentSpanId": decode_id(sp["parentSpanId"]) if "parentSpanId" in sp else None,
        "name": sp["name"],
        "startNs": start_ns,
        "endNs": end_ns,
        "durationMs": (end_ns - start_ns) / 1e6,
        "attrs": important_attrs,
        "jujuEventKind": juju_event_kind,
    }


# ---------------------------------------------------------------------------
# Trace grouping + metadata
# ---------------------------------------------------------------------------


def build_traces(spans: list[dict]) -> list[dict]:
    """Group spans into traces, compute metadata, sort chronologically."""
    by_trace: dict[str, list[dict]] = defaultdict(list)
    for sp in spans:
        by_trace[sp["traceId"]].append(sp)

    traces = []
    for tid, t_spans in by_trace.items():
        root_spans = [s for s in t_spans if s["parentSpanId"] is None]
        root = root_spans[0] if root_spans else t_spans[0]

        trace_start = min(s["startNs"] for s in t_spans)
        trace_end = max(s["endNs"] for s in t_spans)
        duration_ms = (trace_end - trace_start) / 1e6

        event_label = root.get("jujuEventKind") or root["name"]

        traces.append(
            {
                "traceId": tid,
                "spans": t_spans,
                "rootSpanId": root["spanId"],
                "traceStart": trace_start,
                "traceEnd": trace_end,
                "durationMs": duration_ms,
                "spanCount": len(t_spans),
                "eventLabel": event_label,
            }
        )

    traces.sort(key=lambda t: t["traceStart"])
    return traces


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wazuh Charm Traces — Flame Graph</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: ui-monospace, "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  background: #0f172a;
  color: #e2e8f0;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
#header {
  background: #1e293b;
  border-bottom: 1px solid #334155;
  padding: 10px 16px;
  flex-shrink: 0;
}
#header h1 { font-size: 14px; color: #94a3b8; font-weight: 400; }
#header span { color: #38bdf8; font-weight: 600; }
#layout {
  display: flex;
  flex: 1;
  overflow: hidden;
}
#trace-index {
  width: 260px;
  min-width: 200px;
  background: #1e293b;
  border-right: 1px solid #334155;
  overflow-y: auto;
  flex-shrink: 0;
}
#trace-index h2 {
  font-size: 11px;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 10px 12px 6px;
  border-bottom: 1px solid #334155;
  position: sticky;
  top: 0;
  background: #1e293b;
  z-index: 1;
}
.trace-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 8px 12px;
  cursor: pointer;
  border-bottom: 1px solid #1e293b;
  transition: background 0.1s;
  position: relative;
}
.trace-item:hover { background: #273040; }
.trace-item.selected { background: #1d3a5f; border-left: 3px solid #38bdf8; padding-left: 9px; }
.trace-item .event-name {
  font-size: 11px;
  color: #cbd5e1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  font-weight: 500;
}
.trace-item .meta {
  font-size: 10px;
  color: #64748b;
  display: flex;
  gap: 8px;
}
.trace-item .dur-bar {
  height: 3px;
  background: #334155;
  border-radius: 2px;
  margin-top: 3px;
  overflow: hidden;
}
.trace-item .dur-fill {
  height: 100%;
  border-radius: 2px;
  transition: width 0.2s;
}
.trace-item.big .event-name { color: #fbbf24; }
.trace-item.big .dur-fill { background: #f59e0b; }
.trace-item:not(.big) .dur-fill { background: #38bdf8; }
#main {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: #0f172a;
}
#breadcrumb {
  background: #1e293b;
  border-bottom: 1px solid #334155;
  padding: 6px 14px;
  font-size: 11px;
  color: #64748b;
  flex-shrink: 0;
  min-height: 30px;
  display: flex;
  align-items: center;
  gap: 4px;
  flex-wrap: wrap;
}
.bc-item { color: #38bdf8; cursor: pointer; text-decoration: underline; text-underline-offset: 2px; }
.bc-item:hover { color: #7dd3fc; }
.bc-sep { color: #475569; }
#flamegraph-wrap {
  flex: 1;
  overflow: auto;
  position: relative;
  padding: 10px 14px;
}
#flamegraph-wrap.empty-state {
  display: flex;
  align-items: center;
  justify-content: center;
  color: #475569;
  font-size: 13px;
}
#flamegraph-svg { display: block; cursor: default; }
#detail {
  background: #1e293b;
  border-top: 1px solid #334155;
  padding: 8px 14px;
  flex-shrink: 0;
  min-height: 56px;
  font-size: 11px;
  color: #94a3b8;
  overflow: hidden;
}
#detail .detail-name {
  font-size: 12px;
  color: #e2e8f0;
  font-weight: 600;
  margin-bottom: 4px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
#detail .detail-attrs { display: flex; flex-wrap: wrap; gap: 6px 16px; }
#detail .attr-pair { color: #64748b; }
#detail .attr-pair span { color: #94a3b8; }
#tooltip {
  position: fixed;
  background: #1e293b;
  border: 1px solid #475569;
  border-radius: 6px;
  padding: 8px 10px;
  font-size: 11px;
  pointer-events: none;
  z-index: 1000;
  max-width: 360px;
  box-shadow: 0 4px 16px rgba(0,0,0,0.5);
  display: none;
}
#tooltip .tt-name { font-weight: 600; color: #e2e8f0; margin-bottom: 4px; word-break: break-all; }
#tooltip .tt-dur { color: #38bdf8; margin-bottom: 4px; }
#tooltip .tt-attr { color: #94a3b8; margin-top: 2px; }
#tooltip .tt-attr b { color: #64748b; font-weight: 400; }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0f172a; }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #475569; }
</style>
</head>
<body>
<div id="header">
  <h1>Wazuh Server Charm — <span>Distributed Traces</span>
    &nbsp;|  <span id="summary-stats"></span>
  </h1>
</div>
<div id="layout">
  <div id="trace-index">
    <h2>Traces</h2>
    <div id="trace-list"></div>
  </div>
  <div id="main">
    <div id="breadcrumb">Select a trace to view its flame graph</div>
    <div id="flamegraph-wrap" class="empty-state">
      <div>← Select a trace from the index</div>
    </div>
    <div id="detail">
      <div style="color:#475569">Hover or click a span for details</div>
    </div>
  </div>
</div>
<div id="tooltip"></div>

<script>
const TRACES = TRACES_JSON_PLACEHOLDER;

function spanColor(name) {
  if (/^ops\\.main$|^ops\\.tracing/.test(name)) return '#6b21a8';
  if (/^reconcile$|_relation_changed.*WazuhServerCharm/.test(name)) return '#1d4ed8';
  if (/^pebble /.test(name)) return '#0d9488';
  if (/opensearch|OpenSearch/i.test(name)) return '#ea580c';
  if (/^(relation-|secret-|is-leader|app-version-set|status-set|config-get)/.test(name)) return '#64748b';
  return '#334155';
}
function spanColorHover(name) {
  const map = {
    '#6b21a8': '#7c3aed', '#1d4ed8': '#2563eb', '#0d9488': '#14b8a6',
    '#ea580c': '#f97316', '#64748b': '#94a3b8', '#334155': '#475569',
  };
  return map[spanColor(name)] || spanColor(name);
}
function fmtDur(ms) {
  if (ms >= 1000) return (ms / 1000).toFixed(2) + 's';
  if (ms >= 1)    return ms.toFixed(1) + 'ms';
  return (ms * 1000).toFixed(0) + 'µs';
}
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function buildTree(spans) {
  const children = {};
  let root = null;
  for (const sp of spans) children[sp.spanId] = [];
  for (const sp of spans) {
    if (sp.parentSpanId === null) root = sp;
    else if (children[sp.parentSpanId] !== undefined) children[sp.parentSpanId].push(sp);
  }
  for (const id of Object.keys(children)) children[id].sort((a, b) => a.startNs - b.startNs);
  return { children, root };
}

function assignDepths(tree) {
  const depths = {};
  function dfs(span, depth) {
    depths[span.spanId] = depth;
    for (const child of tree.children[span.spanId] || []) dfs(child, depth + 1);
  }
  if (tree.root) dfs(tree.root, 0);
  return depths;
}

const ROW_H = 20;
const SVG_NS = 'http://www.w3.org/2000/svg';
let currentTrace = null, zoomStack = [], tree = null, depths = null, hoveredEl = null;

function renderFlamegraph(trace, zoomSpan) {
  const wrap = document.getElementById('flamegraph-wrap');
  wrap.classList.remove('empty-state');
  if (!tree || currentTrace !== trace) {
    tree = buildTree(trace.spans);
    depths = assignDepths(tree);
    currentTrace = trace;
  }
  const viewStart = zoomSpan ? zoomSpan.startNs : trace.traceStart;
  const viewEnd   = zoomSpan ? zoomSpan.endNs   : trace.traceEnd;
  const viewDurNs = viewEnd - viewStart;
  const maxDepth = Math.max(...Object.values(depths));
  const svgH = (maxDepth + 1) * ROW_H + 4;
  const svgW = Math.max(wrap.clientWidth - 4, 400);
  const oldSvg = document.getElementById('flamegraph-svg');
  if (oldSvg) oldSvg.remove();
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.id = 'flamegraph-svg';
  svg.setAttribute('width', svgW);
  svg.setAttribute('height', svgH);
  const bg = document.createElementNS(SVG_NS, 'rect');
  bg.setAttribute('x', 0); bg.setAttribute('y', 0);
  bg.setAttribute('width', svgW); bg.setAttribute('height', svgH);
  bg.setAttribute('fill', '#0f172a');
  bg.addEventListener('dblclick', () => zoomOut());
  svg.appendChild(bg);
  function nsToX(ns) { return ((ns - viewStart) / viewDurNs) * svgW; }
  for (const sp of trace.spans) {
    const depth = depths[sp.spanId];
    if (depth === undefined) continue;
    const x1 = nsToX(sp.startNs);
    const w = Math.max(nsToX(sp.endNs) - x1, 1);
    const y = svgH - (depth + 1) * ROW_H;
    const fill = spanColor(sp.name);
    const g = document.createElementNS(SVG_NS, 'g');
    const rect = document.createElementNS(SVG_NS, 'rect');
    rect.setAttribute('x', x1); rect.setAttribute('y', y + 1);
    rect.setAttribute('width', Math.max(w - 1, 1)); rect.setAttribute('height', ROW_H - 2);
    rect.setAttribute('fill', fill); rect.setAttribute('rx', 2);
    g.appendChild(rect);
    if (w > 20) {
      const chars = Math.floor((w - 8) / 6);
      let label = sp.name;
      if (chars >= 3) {
        if (label.length > chars) label = label.slice(0, chars - 1) + '…';
        const clipId = 'clip-' + sp.spanId;
        const defs = document.createElementNS(SVG_NS, 'defs');
        const cp = document.createElementNS(SVG_NS, 'clipPath');
        cp.id = clipId;
        const cr = document.createElementNS(SVG_NS, 'rect');
        cr.setAttribute('x', x1 + 2); cr.setAttribute('y', y + 1);
        cr.setAttribute('width', Math.max(w - 4, 0)); cr.setAttribute('height', ROW_H - 2);
        cp.appendChild(cr); defs.appendChild(cp); g.appendChild(defs);
        const txt = document.createElementNS(SVG_NS, 'text');
        txt.setAttribute('x', x1 + 4); txt.setAttribute('y', y + ROW_H - 6);
        txt.setAttribute('font-size', 10); txt.setAttribute('fill', '#e2e8f0');
        txt.setAttribute('pointer-events', 'none');
        txt.setAttribute('clip-path', 'url(#' + clipId + ')');
        txt.textContent = label;
        g.appendChild(txt);
      }
    }
    g.style.cursor = 'pointer';
    g.addEventListener('mouseenter', (e) => onSpanHover(e, sp, rect, fill));
    g.addEventListener('mousemove', (e) => moveTooltip(e));
    g.addEventListener('mouseleave', () => onSpanLeave(rect));
    g.addEventListener('click', (e) => { e.stopPropagation(); onSpanClick(sp); });
    svg.appendChild(g);
  }
  const numTicks = Math.min(10, Math.floor(svgW / 80));
  for (let i = 0; i <= numTicks; i++) {
    const x = (i / numTicks) * svgW;
    const fracNs = (viewDurNs / numTicks) * i;
    const line = document.createElementNS(SVG_NS, 'line');
    line.setAttribute('x1', x); line.setAttribute('y1', 0);
    line.setAttribute('x2', x); line.setAttribute('y2', svgH);
    line.setAttribute('stroke', '#1e293b'); line.setAttribute('stroke-width', 1);
    svg.insertBefore(line, svg.children[1]);
    const lbl = document.createElementNS(SVG_NS, 'text');
    lbl.setAttribute('x', x + 2); lbl.setAttribute('y', 10);
    lbl.setAttribute('font-size', 9); lbl.setAttribute('fill', '#334155');
    lbl.setAttribute('pointer-events', 'none');
    lbl.textContent = fmtDur(fracNs / 1e6);
    svg.appendChild(lbl);
  }
  wrap.appendChild(svg);
  updateBreadcrumb();
}

function onSpanClick(sp) {
  zoomStack.push({ spanId: sp.spanId, startNs: sp.startNs, endNs: sp.endNs, name: sp.name });
  renderFlamegraph(currentTrace, sp);
  showDetail(sp);
}
function zoomOut() {
  if (zoomStack.length === 0) return;
  zoomStack.pop();
  const top = zoomStack[zoomStack.length - 1];
  renderFlamegraph(currentTrace, top ? { startNs: top.startNs, endNs: top.endNs } : null);
}
function zoomToLevel(level) {
  if (level < 0) { zoomStack = []; renderFlamegraph(currentTrace, null); return; }
  zoomStack = zoomStack.slice(0, level + 1);
  const top = zoomStack[zoomStack.length - 1];
  renderFlamegraph(currentTrace, { startNs: top.startNs, endNs: top.endNs });
}
function updateBreadcrumb() {
  const bc = document.getElementById('breadcrumb');
  if (!currentTrace) { bc.textContent = 'Select a trace to view its flame graph'; return; }
  bc.innerHTML = '';
  const root = document.createElement('span');
  root.className = 'bc-item';
  root.textContent = currentTrace.eventLabel;
  root.addEventListener('click', () => zoomToLevel(-1));
  bc.appendChild(root);
  zoomStack.forEach((entry, i) => {
    const sep = document.createElement('span'); sep.className = 'bc-sep'; sep.textContent = ' › ';
    bc.appendChild(sep);
    const item = document.createElement('span'); item.className = 'bc-item';
    item.textContent = entry.name.length > 40 ? entry.name.slice(0, 39) + '…' : entry.name;
    const idx = i; item.addEventListener('click', () => zoomToLevel(idx));
    bc.appendChild(item);
  });
  if (zoomStack.length > 0) {
    const hint = document.createElement('span');
    hint.style.color = '#334155'; hint.style.marginLeft = '8px';
    hint.textContent = '(double-click background to zoom out)';
    bc.appendChild(hint);
  }
}

const tooltip = document.getElementById('tooltip');
function onSpanHover(e, sp, rect, origFill) {
  if (hoveredEl && hoveredEl !== rect) hoveredEl.setAttribute('fill', hoveredEl._origFill);
  rect._origFill = origFill;
  rect.setAttribute('fill', spanColorHover(sp.name));
  hoveredEl = rect;
  let html = '<div class="tt-name">' + escHtml(sp.name) + '</div>';
  html += '<div class="tt-dur">' + fmtDur(sp.durationMs) + '</div>';
  for (const [k, v] of Object.entries(sp.attrs)) {
    const val = v.length > 80 ? v.slice(0, 79) + '…' : v;
    html += '<div class="tt-attr"><b>' + escHtml(k) + ':</b> ' + escHtml(val) + '</div>';
  }
  tooltip.innerHTML = html; tooltip.style.display = 'block'; moveTooltip(e);
  showDetail(sp);
}
function moveTooltip(e) {
  const margin = 12;
  let left = e.clientX + margin, top = e.clientY + margin;
  if (left + tooltip.offsetWidth  > window.innerWidth  - 4) left = e.clientX - tooltip.offsetWidth  - margin;
  if (top  + tooltip.offsetHeight > window.innerHeight - 4) top  = e.clientY - tooltip.offsetHeight - margin;
  tooltip.style.left = left + 'px'; tooltip.style.top = top + 'px';
}
function onSpanLeave(rect) {
  rect.setAttribute('fill', rect._origFill || spanColor(''));
  tooltip.style.display = 'none';
}
function showDetail(sp) {
  const det = document.getElementById('detail');
  let html = '<div class="detail-name">' + escHtml(sp.name) + '</div><div class="detail-attrs">';
  html += '<div class="attr-pair">duration: <span>' + fmtDur(sp.durationMs) + '</span></div>';
  html += '<div class="attr-pair">spanId: <span>' + sp.spanId.slice(0, 16) + '…</span></div>';
  for (const [k, v] of Object.entries(sp.attrs)) {
    const val = v.length > 120 ? v.slice(0, 119) + '…' : v;
    html += '<div class="attr-pair">' + escHtml(k) + ': <span>' + escHtml(val) + '</span></div>';
  }
  det.innerHTML = html + '</div>';
}

function buildTraceIndex() {
  const list = document.getElementById('trace-list');
  const maxDur = Math.max(...TRACES.map(t => t.durationMs));
  const stats = document.getElementById('summary-stats');
  stats.textContent = TRACES.length + ' traces · ' + TRACES.reduce((a, t) => a + t.spanCount, 0) + ' spans';
  TRACES.forEach((trace, i) => {
    const isBig = trace.durationMs >= 5000;
    const div = document.createElement('div');
    div.className = 'trace-item' + (isBig ? ' big' : '');
    div.title = 'traceId: ' + trace.traceId;
    const name = document.createElement('div'); name.className = 'event-name'; name.textContent = trace.eventLabel;
    const meta = document.createElement('div'); meta.className = 'meta';
    meta.innerHTML = '<span>' + fmtDur(trace.durationMs) + '</span><span>' + trace.spanCount + ' spans</span>';
    const bar = document.createElement('div'); bar.className = 'dur-bar';
    const fill = document.createElement('div'); fill.className = 'dur-fill';
    fill.style.width = Math.max((trace.durationMs / maxDur) * 100, 2) + '%';
    bar.appendChild(fill);
    div.append(name, meta, bar);
    div.addEventListener('click', () => selectTrace(i, div));
    list.appendChild(div);
  });
}

function selectTrace(idx, el) {
  document.querySelectorAll('.trace-item.selected').forEach(e => e.classList.remove('selected'));
  el.classList.add('selected');
  zoomStack = []; tree = null; depths = null;
  renderFlamegraph(TRACES[idx], null);
}

buildTraceIndex();
const firstItem = document.querySelector('.trace-item');
if (firstItem) firstItem.click();

let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (!currentTrace) return;
    const top = zoomStack[zoomStack.length - 1];
    renderFlamegraph(currentTrace, top ? { startNs: top.startNs, endNs: top.endNs } : null);
  }, 150);
});
</script>
</body>
</html>
"""


def build_html(traces: list[dict]) -> str:
    """Render the self-contained HTML page with embedded trace data."""
    traces_json = json.dumps(traces, separators=(",", ":"))
    return _HTML_TEMPLATE.replace("TRACES_JSON_PLACEHOLDER", traces_json)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Generate flamegraph.html from an OTLP JSON traces file."""
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input-traces.json> <output-flamegraph.html>")
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]
    print(f"Loading spans from {input_path} ...")
    raw_spans = load_spans(input_path)
    print(f"  {len(raw_spans)} spans loaded")

    spans = [parse_span(sp) for sp in raw_spans]
    traces = build_traces(spans)
    print(f"  {len(traces)} traces found")

    html = build_html(traces)
    with open(output_path, "w") as f:
        f.write(html)
    print(f"Wrote {len(html):,} bytes to {output_path}")


if __name__ == "__main__":
    main()
