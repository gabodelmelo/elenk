"""HTML report: an interactive terminal/hacker-style dashboard for
browsing ALL findings from a scan, with filters by severity, tool,
category, and free text.

It's a single self-contained HTML file (inline CSS and JS, no CDN or
external dependencies) so it can be opened offline or attached to a
ticket/email without the styling breaking.

This module exposes the reusable pieces (visual theme, base layout,
dashboard section, filterable findings section) used to build the
report in `to_html`.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from elenk.core.models import Finding, ScanResult, Severity

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]

SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff2b4d",
    Severity.HIGH: "#ff8c2b",
    Severity.MEDIUM: "#f4d03f",
    Severity.LOW: "#39c5ff",
    Severity.INFO: "#7f9f8f",
    Severity.UNKNOWN: "#6b7a70",
}

_MAX_DESCRIPTION_CHARS = 140
_MAX_DESCRIPTION_HARD_CAP = 200


def esc_html(value: object) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _shorten(text: str, limit: int = _MAX_DESCRIPTION_CHARS, hard_cap: int = _MAX_DESCRIPTION_HARD_CAP) -> str:
    """Keeps only a short teaser of a finding's description: the first
    sentence when there is one nearby, otherwise a clean cut at a word
    boundary — never a hard chop mid-word, which reads like the text
    got cut off by accident rather than shortened on purpose."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text

    window = text[:hard_cap]
    for end in (". ", "! ", "? "):
        idx = window.find(end)
        if idx != -1:
            return window[: idx + 1].strip()

    cut = text.rfind(" ", 0, limit)
    if cut <= 0:
        cut = limit
    return text[:cut].rstrip() + "…"


def _location(finding: Finding) -> str:
    if not finding.file_path:
        return "(no specific file)"
    loc = finding.file_path
    if finding.line:
        loc += f":{finding.line}"
    return loc


# ---------------------------------------------------------------------------
# Shared visual theme (CSS + JS), no CDNs or external dependencies.
# ---------------------------------------------------------------------------

THEME_CSS = """
:root {
  --bg: #04070a;
  --border: #1c3b2a;
  --border-bright: #00ff6a;
  --fg: #c8f7d8;
  --fg-dim: #5f9c78;
  --green: #00ff6a;
  --green-dim: #0a8f45;
  --mono: ui-monospace, "Cascadia Code", "Fira Code", Consolas, "Courier New", monospace;
}
* { box-sizing: border-box; }
html, body { background: var(--bg); }
body {
  margin: 0; color: var(--fg); font-family: var(--mono); font-size: 14px;
  line-height: 1.4; position: relative;
}
#matrix-rain { position: fixed; inset: 0; z-index: 0; opacity: .16; }
.scanlines {
  position: fixed; inset: 0; z-index: 2; pointer-events: none; mix-blend-mode: overlay;
  background: repeating-linear-gradient(
    rgba(0,0,0,0) 0px, rgba(0,0,0,0) 1px,
    rgba(0,255,106,.035) 2px, rgba(0,0,0,0) 3px
  );
}
.wrap { position: relative; z-index: 1; max-width: 1100px; margin: 0 auto; padding: 32px 20px 80px; }

.term-header {
  border: 1px solid var(--border-bright); border-radius: 6px;
  background: linear-gradient(180deg, rgba(0,255,106,.07), transparent);
  padding: 20px 24px; margin-bottom: 24px;
  box-shadow: 0 0 24px rgba(0,255,106,.08) inset;
}
.term-header .prompt { color: var(--green-dim); font-size: 12.5px; overflow-wrap: anywhere; }
.term-header h1 {
  margin: 6px 0 4px; font-size: 22px; color: var(--green);
  text-shadow: 0 0 8px rgba(0,255,106,.5); letter-spacing: .02em;
}
.cursor {
  display: inline-block; width: 9px; height: 18px; background: var(--green);
  margin-left: 4px; vertical-align: -3px; animation: blink 1s steps(1) infinite;
}
@keyframes blink { 50% { opacity: 0; } }
.meta-line { color: var(--fg-dim); font-size: 12.5px; margin-top: 4px; overflow-wrap: anywhere; }
.badge {
  display: inline-block; border: 1px solid var(--green-dim); color: var(--green);
  padding: 1px 8px; border-radius: 3px; font-size: 10.5px; letter-spacing: .08em;
  text-transform: uppercase; margin-right: 8px;
}

.panel {
  border: 1px solid var(--border); background: rgba(6,14,10,.7);
  border-radius: 6px; padding: 18px 20px; margin-bottom: 22px;
}
.panel h2 {
  margin: 0 0 14px; font-size: 14px; color: var(--green); letter-spacing: .06em;
  text-transform: uppercase; border-bottom: 1px dashed var(--border); padding-bottom: 8px;
}
.panel h2::before { content: "// "; color: var(--green-dim); }

.score-box { display: flex; gap: 28px; align-items: center; flex-wrap: wrap; }
.score-gauge { text-align: center; }
.score-n { font-size: 52px; font-weight: 700; line-height: 1; }
.score-max { font-size: 22px; color: var(--fg-dim); }
.score-label { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; margin-top: 6px; }
.score-narrative { flex: 1; min-width: 240px; font-size: 13px; color: var(--fg); line-height: 1.5; }

.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; margin-bottom: 16px; }
.stat-card {
  border: 1px solid var(--border); border-radius: 5px; padding: 12px 10px; text-align: center;
  cursor: pointer; background: rgba(0,0,0,.25); transition: transform .12s, border-color .12s;
}
.stat-card:hover { transform: translateY(-2px); border-color: var(--green-dim); }
.stat-card.active { border-color: var(--sc, var(--green)); box-shadow: 0 0 12px var(--sc, var(--green)); }
.stat-card .n { font-size: 26px; font-weight: 700; color: var(--fg); }
.stat-card .l { font-size: 10px; letter-spacing: .08em; color: var(--fg-dim); text-transform: uppercase; margin-top: 2px; }

.sev-bar { display: flex; height: 10px; border-radius: 4px; overflow: hidden; border: 1px solid var(--border); margin-bottom: 18px; }
.sev-bar span { height: 100%; }

.table-wrap { overflow-x: auto; margin-bottom: 4px; }
.table { width: 100%; min-width: 420px; border-collapse: collapse; font-size: 12.5px; }
.table th, .table td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
.table th { color: var(--green-dim); text-transform: uppercase; font-size: 10.5px; letter-spacing: .06em; white-space: nowrap; }
.status-warn { color: #f4d03f; }
.status-skip { color: var(--fg-dim); }
.status-ok { color: var(--green); }

.filter-bar {
  display: flex; flex-wrap: wrap; gap: 14px; align-items: flex-end; margin-bottom: 12px;
  padding: 14px; border: 1px solid var(--border); border-radius: 5px; background: rgba(0,0,0,.2);
}
.filter-group { display: flex; flex-direction: column; gap: 4px; }
.filter-group label { font-size: 10px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: .06em; }
select, input[type=text] {
  background: #05100a; color: var(--fg); border: 1px solid var(--border); border-radius: 4px;
  padding: 6px 8px; font-family: var(--mono); font-size: 12.5px;
}
select:focus, input:focus { outline: none; border-color: var(--green); box-shadow: 0 0 6px rgba(0,255,106,.4); }
.chip-group { display: flex; gap: 6px; flex-wrap: wrap; }
.chip {
  border: 1px solid var(--border); background: transparent; color: var(--fg-dim);
  padding: 5px 10px; border-radius: 20px; font-family: var(--mono); font-size: 11px;
  cursor: pointer; letter-spacing: .04em; text-transform: uppercase;
}
.chip.active { color: #04070a; background: var(--cc, var(--green)); border-color: var(--cc, var(--green)); }
.btn-reset {
  margin-left: auto; background: transparent; border: 1px solid var(--border); color: var(--fg-dim);
  padding: 7px 12px; border-radius: 4px; cursor: pointer; font-family: var(--mono); font-size: 11px;
}
.btn-reset:hover { border-color: #ff2b4d; color: #ff2b4d; }
.filter-status { font-size: 11.5px; color: var(--fg-dim); margin-bottom: 12px; }
.filter-status b { color: var(--green); }

.finding-card {
  border: 1px solid var(--border); border-left: 3px solid var(--sc, var(--green)); border-radius: 5px;
  padding: 14px 16px; margin-bottom: 10px; background: rgba(0,0,0,.2);
}
.finding-card[hidden] { display: none; }
.finding-card header { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.finding-card h3 { margin: 0; font-size: 13.5px; color: var(--fg); overflow-wrap: anywhere; }
.sev-tag { font-size: 10px; font-weight: 700; letter-spacing: .06em; padding: 2px 7px; border-radius: 3px; color: #04070a; background: var(--sc, var(--green)); }
.finding-meta { font-size: 11px; color: var(--fg-dim); margin: 6px 0 8px; overflow-wrap: anywhere; }
.finding-meta code { color: var(--green-dim); }
.finding-desc { font-size: 12.5px; color: var(--fg); line-height: 1.5; margin-bottom: 8px; overflow-wrap: anywhere; }
.remediation { border-left: 3px solid var(--green); background: rgba(0,255,106,.06); padding: 8px 10px; font-size: 12px; margin-top: 8px; overflow-wrap: anywhere; }
.remediation b { color: var(--green); }
.owasp-tags { margin-bottom: 6px; }
.owasp-tags span { display: inline-block; border: 1px solid var(--border); color: var(--fg-dim); font-size: 10px; padding: 1px 6px; border-radius: 3px; margin: 2px 4px 0 0; }
.empty-state { color: var(--fg-dim); font-size: 12.5px; }

.footer { color: var(--fg-dim); font-size: 10.5px; margin-top: 36px; border-top: 1px dashed var(--border); padding-top: 14px; }

@media (max-width: 620px) {
  .filter-bar { flex-direction: column; align-items: stretch; }
  .btn-reset { margin-left: 0; }
}
"""

MATRIX_JS = """
(function () {
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var canvas = document.getElementById('matrix-rain');
  if (!canvas || reduce) return;
  var ctx = canvas.getContext('2d');
  var chars = 'アイウエオカキクケコサシスセソ0123456789ABCDEF$#%&';
  var fontSize = 14;
  var columns, drops;
  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    columns = Math.floor(canvas.width / fontSize);
    drops = new Array(columns).fill(1);
  }
  window.addEventListener('resize', resize);
  resize();
  function draw() {
    ctx.fillStyle = 'rgba(4,7,10,0.08)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#00ff6a';
    ctx.font = fontSize + 'px monospace';
    for (var i = 0; i < drops.length; i++) {
      var text = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  setInterval(draw, 50);
})();
"""

FILTER_JS = """
(function () {
  var SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };
  var list = document.querySelector('[data-role="list"]');
  if (!list) return;
  var cards = Array.prototype.slice.call(list.querySelectorAll('.finding-card'));
  var chips = Array.prototype.slice.call(document.querySelectorAll('.chip[data-sev]'));
  var toolSel = document.getElementById('f-tool');
  var catSel = document.getElementById('f-cat');
  var q = document.getElementById('f-q');
  var sortSel = document.getElementById('f-sort');
  var resetBtn = document.querySelector('[data-role="reset"]');
  var countEl = document.querySelector('[data-role="count"]');
  var statCards = Array.prototype.slice.call(document.querySelectorAll('.stat-card[data-sev]'));
  var allSevCard = document.querySelector('[data-role="all-sev"]');

  function activeSevs() {
    return chips.filter(function (c) { return c.classList.contains('active'); })
      .map(function (c) { return c.dataset.sev; });
  }

  function sortCards() {
    var mode = sortSel ? sortSel.value : 'severity';
    var ordered = cards.slice();
    ordered.sort(function (a, b) {
      if (mode === 'file') return (a.dataset.file || '').localeCompare(b.dataset.file || '');
      if (mode === 'tool') return (a.dataset.tool || '').localeCompare(b.dataset.tool || '');
      return SEV_RANK[b.dataset.severity] - SEV_RANK[a.dataset.severity];
    });
    ordered.forEach(function (card) { list.appendChild(card); });
  }

  function apply() {
    var sevs = activeSevs();
    var tool = toolSel ? toolSel.value : 'all';
    var cat = catSel ? catSel.value : 'all';
    var text = (q ? q.value : '').trim().toLowerCase();
    var shown = 0;
    cards.forEach(function (card) {
      var ok = sevs.indexOf(card.dataset.severity) !== -1;
      if (ok && tool !== 'all') ok = card.dataset.tool === tool;
      if (ok && cat !== 'all') ok = card.dataset.category === cat;
      if (ok && text) ok = card.dataset.search.indexOf(text) !== -1;
      card.hidden = !ok;
      if (ok) shown++;
    });
    if (countEl) countEl.textContent = shown;
    statCards.forEach(function (sc) {
      sc.classList.toggle('active', sevs.length === 1 && sevs[0] === sc.dataset.sev);
    });
    sortCards();
  }

  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      chip.classList.toggle('active');
      if (!chips.some(function (c) { return c.classList.contains('active'); })) {
        chips.forEach(function (c) { c.classList.add('active'); });
      }
      apply();
    });
  });

  statCards.forEach(function (sc) {
    sc.addEventListener('click', function () {
      var sev = sc.dataset.sev;
      chips.forEach(function (c) { c.classList.toggle('active', c.dataset.sev === sev); });
      apply();
    });
  });

  if (allSevCard) {
    allSevCard.addEventListener('click', function () {
      chips.forEach(function (c) { c.classList.add('active'); });
      apply();
    });
  }

  [toolSel, catSel, sortSel].forEach(function (el) {
    if (el) el.addEventListener('change', apply);
  });
  if (q) q.addEventListener('input', apply);
  if (resetBtn) {
    resetBtn.addEventListener('click', function () {
      chips.forEach(function (c) { c.classList.add('active'); });
      if (toolSel) toolSel.value = 'all';
      if (catSel) catSel.value = 'all';
      if (q) q.value = '';
      if (sortSel) sortSel.value = 'severity';
      apply();
    });
  }

  apply();
})();
"""


def render_page(title: str, body: str) -> str:
    """Wraps `body` (already-built HTML) in the full document: theme,
    matrix-rain canvas, and the filter script."""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc_html(title)}</title>
<style>{THEME_CSS}</style>
</head>
<body>
<canvas id="matrix-rain"></canvas>
<div class="scanlines"></div>
<div class="wrap">
{body}
</div>
<script>{MATRIX_JS}</script>
<script>{FILTER_JS}</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Reusable sections (score + dashboard + filterable findings)
# ---------------------------------------------------------------------------


def _score_color(score: int) -> str:
    if score >= 90:
        return "#00ff6a"
    if score >= 70:
        return "#f4d03f"
    if score >= 40:
        return "#ff8c2b"
    return "#ff2b4d"


def _score_label(score: int) -> str:
    """Labels the overall score panel, prefixed with "risk level" so it
    can never be mistaken for a per-finding severity tag (e.g. the
    CRITICAL badge on an individual finding) when the panel is shown
    out of context, such as in a screenshot."""
    if score >= 90:
        return "risk level: low"
    if score >= 70:
        return "risk level: moderate"
    if score >= 40:
        return "risk level: elevated"
    return "risk level: critical"


def default_narrative(result: ScanResult) -> str:
    critical = result.summary_by_severity.get("critical", 0)
    high = result.summary_by_severity.get("high", 0)

    if result.total_findings == 0:
        return "No vulnerabilities detected with the scanners that ran. Re-run periodically and on every significant change."
    if critical:
        return f"{critical} CRITICAL and {high} HIGH severity finding(s). Prioritize fixing these before the next release."
    if high:
        return f"No critical findings, but {high} HIGH severity. Plan fixes into the next development cycle."
    return f"{result.total_findings} medium/low severity finding(s). Immediate risk is limited, but worth reviewing."


def render_score_panel(result: ScanResult) -> str:
    """HUD panel with the 0-100 score (100 = no vulnerabilities) plus a
    one-line narrative."""
    score = result.security_score
    color = _score_color(score)
    label = _score_label(score)
    text = default_narrative(result)
    return f"""
<section class="panel">
  <h2>security score</h2>
  <div class="score-box">
    <div class="score-gauge">
      <div class="score-n" style="color:{color};text-shadow:0 0 16px {color};">{score}<span class="score-max">/100</span></div>
      <div class="score-label" style="color:{color};">{esc_html(label)}</div>
    </div>
    <div class="score-narrative">{esc_html(text)}</div>
  </div>
</section>
"""


def render_stat_cards(result: ScanResult) -> str:
    counts = result.summary_by_severity
    cards = [
        '<div class="stat-card stat-total" data-role="all-sev">'
        f'<div class="n">{result.total_findings}</div><div class="l">total</div></div>'
    ]
    for sev in SEVERITY_ORDER:
        count = counts.get(sev.value, 0)
        color = SEVERITY_COLORS[sev]
        cards.append(
            f'<div class="stat-card" data-sev="{sev.value}" style="--sc:{color}">'
            f'<div class="n" style="color:{color}">{count}</div>'
            f'<div class="l">{sev.value}</div></div>'
        )
    return '<div class="stat-grid">' + "".join(cards) + "</div>"


def render_severity_bar(result: ScanResult) -> str:
    total = result.total_findings
    if not total:
        return ""
    counts = result.summary_by_severity
    segments = []
    for sev in SEVERITY_ORDER:
        count = counts.get(sev.value, 0)
        if not count:
            continue
        pct = round(count / total * 100, 2)
        segments.append(
            f'<span style="width:{pct}%;background:{SEVERITY_COLORS[sev]}" '
            f'title="{sev.value}: {count}"></span>'
        )
    return '<div class="sev-bar">' + "".join(segments) + "</div>"


def render_scanner_table(result: ScanResult) -> str:
    rows = []
    for run in result.scanner_runs:
        if run.ran:
            status = "ran" if not run.error else f"ran with error: {esc_html(run.error)}"
            status_class = "ok" if not run.error else "warn"
        elif not run.applicable:
            status = "not applicable"
            status_class = "skip"
        else:
            status = f"skipped — {esc_html(run.skipped_reason or '')}"
            status_class = "skip"
        rows.append(
            "<tr>"
            f"<td>{esc_html(run.tool)}</td>"
            f'<td class="status-{status_class}">{status}</td>'
            f"<td>{run.finding_count}</td>"
            f"<td>{run.duration_seconds:.1f}s</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table class="table"><thead><tr><th>tool</th><th>status</th>'
        "<th>findings</th><th>duration</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def render_dashboard_section(result: ScanResult) -> str:
    return (
        '<section class="panel">'
        "<h2>dashboard</h2>"
        + render_stat_cards(result)
        + render_severity_bar(result)
        + render_scanner_table(result)
        + "</section>"
    )


def _render_finding_card(
    finding: Finding, owasp_for: Optional[Callable[[Finding], List[str]]]
) -> str:
    color = SEVERITY_COLORS.get(finding.severity, SEVERITY_COLORS[Severity.UNKNOWN])
    location = _location(finding)
    search_blob = " ".join(
        str(part)
        for part in [
            finding.title,
            finding.description,
            finding.rule_id,
            finding.tool,
            finding.file_path,
            finding.package_name,
        ]
        if part
    ).lower()

    meta_bits = [f"{esc_html(finding.tool)} · rule <code>{esc_html(finding.rule_id)}</code>", esc_html(location)]
    if finding.package_name:
        version = finding.installed_version or "?"
        pkg = f"{finding.package_name}@{version}"
        if finding.fixed_version:
            pkg += f" -> {finding.fixed_version}"
        meta_bits.append(esc_html(pkg))
    if finding.cwe_ids:
        meta_bits.append("CWE " + ", ".join(esc_html(c) for c in finding.cwe_ids))

    owasp_tags = ""
    if owasp_for:
        tags = owasp_for(finding)
        if tags:
            owasp_tags = '<div class="owasp-tags">' + "".join(f"<span>{esc_html(t)}</span>" for t in tags) + "</div>"

    description = (
        f'<div class="finding-desc">{esc_html(_shorten(finding.description))}</div>' if finding.description else ""
    )
    remediation = (
        f'<div class="remediation"><b>fix:</b> {esc_html(finding.remediation)}</div>' if finding.remediation else ""
    )

    return (
        f'<article class="finding-card" data-severity="{finding.severity.value}" '
        f'data-tool="{esc_html(finding.tool)}" data-category="{esc_html(finding.category.value)}" '
        f'data-file="{esc_html(finding.file_path or "")}" data-search="{esc_html(search_blob)}" '
        f'style="--sc:{color}">'
        f'<header><span class="sev-tag" style="--sc:{color}">{finding.severity.value.upper()}</span>'
        f"<h3>{esc_html(finding.title)}</h3></header>"
        f'<div class="finding-meta">{" · ".join(meta_bits)}</div>'
        + owasp_tags
        + description
        + remediation
        + "</article>"
    )


def render_findings_section(
    result: ScanResult, owasp_for: Optional[Callable[[Finding], List[str]]] = None
) -> str:
    findings = result.sorted_findings()
    tools = sorted({f.tool for f in findings})
    categories = sorted({f.category.value for f in findings})

    tool_options = "".join(f'<option value="{esc_html(t)}">{esc_html(t)}</option>' for t in tools)
    cat_options = "".join(f'<option value="{esc_html(c)}">{esc_html(c)}</option>' for c in categories)

    chips = "".join(
        f'<button type="button" class="chip active" data-sev="{sev.value}" '
        f'style="--cc:{SEVERITY_COLORS[sev]}">{sev.value}</button>'
        for sev in SEVERITY_ORDER
    )

    cards = "".join(_render_finding_card(f, owasp_for) for f in findings) or (
        '<p class="empty-state">no findings with the scanners that ran.</p>'
    )

    filter_bar = f"""
<div class="filter-bar">
  <div class="filter-group">
    <label>severity</label>
    <div class="chip-group">{chips}</div>
  </div>
  <div class="filter-group">
    <label for="f-tool">tool</label>
    <select id="f-tool"><option value="all">all</option>{tool_options}</select>
  </div>
  <div class="filter-group">
    <label for="f-cat">category</label>
    <select id="f-cat"><option value="all">all</option>{cat_options}</select>
  </div>
  <div class="filter-group search-group">
    <label for="f-q">search</label>
    <input id="f-q" type="text" placeholder="title, file, rule...">
  </div>
  <div class="filter-group">
    <label for="f-sort">sort by</label>
    <select id="f-sort">
      <option value="severity">severity</option>
      <option value="file">file</option>
      <option value="tool">tool</option>
    </select>
  </div>
  <button type="button" class="btn-reset" data-role="reset">clear filters</button>
</div>
<div class="filter-status">showing <b data-role="count">{len(findings)}</b> of {len(findings)} findings</div>
"""

    return (
        '<section class="panel">'
        "<h2>findings</h2>"
        + filter_bar
        + f'<div class="findings-list" data-role="list">{cards}</div>'
        + "</section>"
    )


# ---------------------------------------------------------------------------
# Full OSS report
# ---------------------------------------------------------------------------


def to_html(result: ScanResult) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    commit_bit = f" · commit: {esc_html(result.commit_sha[:12])}" if result.commit_sha else ""
    header = f"""
<div class="term-header">
  <span class="badge">Elenk</span>
  <div class="prompt">user@elenk:~$ elenk scan {esc_html(result.repo_url)}</div>
  <h1>vulnerability report<span class="cursor"></span></h1>
  <div class="meta-line">
    repo: {esc_html(result.repo_name)}{commit_bit}
    · ecosystems: {esc_html(", ".join(result.detected_ecosystems) or "none")}
    · duration: {result.duration_seconds:.1f}s
    · generated: {generated_at}
  </div>
</div>
"""
    footer = """
<footer class="footer">
  Generated by Elenk (open source).
</footer>
"""
    body = (
        header
        + render_score_panel(result)
        + render_dashboard_section(result)
        + render_findings_section(result)
        + footer
    )
    return render_page(title=f"Security report — {result.repo_name}", body=body)


def write_html_report(result: ScanResult, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(to_html(result), encoding="utf-8")
    return output_path
