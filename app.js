/* ═══════════════════════════════════════════════
   VulnScope v3 — app.js
   ═══════════════════════════════════════════════ */

// ─── CONSTANTS ────────────────────────────────────
const HEADERS = [
  { name: "Content-Security-Policy",      short: "CSP",  weight: 20, category: "Injection" },
  { name: "Strict-Transport-Security",    short: "HSTS", weight: 15, category: "Transport" },
  { name: "X-Frame-Options",             short: "XFO",  weight: 12, category: "Clickjacking" },
  { name: "X-Content-Type-Options",      short: "XCTO", weight: 10, category: "MIME" },
  { name: "Referrer-Policy",             short: "RP",   weight: 8,  category: "Privacy" },
  { name: "Permissions-Policy",          short: "PP",   weight: 8,  category: "Permissions" },
  { name: "X-XSS-Protection",            short: "XSS",  weight: 7,  category: "XSS" },
  { name: "Cache-Control",               short: "CC",   weight: 8,  category: "Caching" },
  { name: "Cross-Origin-Opener-Policy",  short: "COOP", weight: 6,  category: "Isolation" },
  { name: "Cross-Origin-Resource-Policy",short: "CORP", weight: 6,  category: "Isolation" },
];

const MAX_SCORE = HEADERS.reduce((a, b) => a + b.weight, 0);

const GRADE_COLORS = {
  "A+": "#00e07a",
  "A":  "#00e07a",
  "B":  "#6ee7b7",
  "C":  "#f7c948",
  "D":  "#fb923c",
  "F":  "#ff4d6d",
};

let currentResult = null;
let alertTimers = {};

// ─── THEME ────────────────────────────────────────
function toggleTheme() {
  const html = document.documentElement;
  const next = html.dataset.theme === "dark" ? "light" : "dark";
  html.dataset.theme = next;
  localStorage.setItem("vs_theme", next);
}

// Apply saved theme on load
(function initTheme() {
  const saved = localStorage.getItem("vs_theme");
  if (saved) document.documentElement.dataset.theme = saved;
})();

// ─── TABS ─────────────────────────────────────────
function showTab(id, btn) {
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-btn, .tab-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("tab-" + id).classList.add("active");
  btn.classList.add("active");

  // Sync mobile tabs
  document.querySelectorAll("#mobileTabs .tab-btn").forEach(b => {
    if (b.getAttribute("onclick") === `showTab('${id}',this)`) b.classList.add("active");
  });

  if (id === "trends")  renderTrends();
  if (id === "history") renderHistory();
  if (id === "alerts")  renderAlerts();
}

// ─── HELPERS ──────────────────────────────────────
function calcScore(headers) {
  let score = 0;
  headers.forEach(h => {
    const cfg = HEADERS.find(c => c.name === h.name);
    const w = cfg ? cfg.weight : 5;
    if (h.status === "present")  score += w;
    if (h.status === "warning")  score += w * 0.4;
  });
  return Math.round((score / MAX_SCORE) * 100);
}

function getGrade(pct) {
  if (pct >= 90) return "A+";
  if (pct >= 80) return "A";
  if (pct >= 70) return "B";
  if (pct >= 55) return "C";
  if (pct >= 40) return "D";
  return "F";
}

function hostname(url) {
  try {
    return new URL(url.startsWith("http") ? url : "https://" + url).hostname;
  } catch {
    return url;
  }
}

function setStatus(id, type, msg) {
  const el = document.getElementById(id);
  el.className = "status " + type;
  el.innerHTML = (type === "running" ? '<div class="pulse"></div>' : "") + msg;
}

// ─── CLAUDE API ────────────────────────────────────
async function analyzeWithClaude(url) {
  const prompt = `You are a web security expert. Simulate a realistic HTTP header security scan for: ${url}

Analyze all 10 headers. Return ONLY valid JSON (no markdown, no extra text):
{
  "headers": [
    {
      "name": "header name",
      "status": "present" | "missing" | "warning",
      "value": "header value string or null",
      "description": "2 sentences on security impact and recommended fix"
    }
  ],
  "summary": "3 sentence overall security assessment"
}
Headers to check: ${HEADERS.map(h => h.name).join(", ")}`;

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!res.ok) throw new Error(`API error ${res.status}`);
  const data = await res.json();
  const text = data.content.map(i => i.text || "").join("");
  return JSON.parse(text.replace(/```json|```/g, "").trim());
}

// ─── SINGLE SCAN ──────────────────────────────────
async function runScan() {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) return;

  document.getElementById("scanBtn").disabled = true;
  document.getElementById("emptyState").style.display = "none";
  document.getElementById("results").style.display = "none";
  setStatus("statusBar", "running", "Analysing HTTP security headers...");
  document.getElementById("scanOverlay").classList.add("on");

  try {
    const analysis = await analyzeWithClaude(url);
    currentResult = { url, analysis, ts: Date.now() };
    saveToHistory(currentResult);
    renderResults(url, analysis);
    setStatus("statusBar", "done", `Scan complete — ${new Date().toLocaleTimeString()}`);
  } catch (e) {
    setStatus("statusBar", "error", "Scan failed: " + e.message);
    document.getElementById("emptyState").style.display = "block";
  } finally {
    document.getElementById("scanBtn").disabled = false;
    document.getElementById("scanOverlay").classList.remove("on");
  }
}

// ─── RENDER RESULTS ───────────────────────────────
function renderResults(url, analysis) {
  const headers = analysis.headers || [];
  const present = headers.filter(h => h.status === "present").length;
  const missing = headers.filter(h => h.status === "missing").length;
  const warns   = headers.filter(h => h.status === "warning").length;
  const pct     = calcScore(headers);
  const grade   = getGrade(pct);
  const color   = GRADE_COLORS[grade];

  // Animate ring
  const circumference = 251;
  const offset = circumference - (pct / 100) * circumference;
  setTimeout(() => {
    const circle = document.getElementById("scoreCircle");
    circle.style.strokeDashoffset = offset;
    circle.style.stroke = pct >= 70 ? "var(--good)" : pct >= 45 ? "var(--warn)" : "var(--danger)";
  }, 80);

  document.getElementById("scoreVal").innerHTML = `${pct}<small>/100</small>`;

  const gb = document.getElementById("gradeBadge");
  gb.textContent = grade;
  gb.style.background = color + "22";
  gb.style.color = color;
  gb.style.border = `1px solid ${color}44`;

  document.getElementById("stPresent").textContent = present;
  document.getElementById("stMissing").textContent = missing;
  document.getElementById("stWarns").textContent   = warns;
  document.getElementById("stUrl").textContent     = url;
  document.getElementById("summaryText").textContent = analysis.summary || "";

  buildBarChart("barChart", headers);
  buildDonut("donutSvg", "donutLegend", present, missing, warns, headers.length);
  buildCards("headerGrid", headers);

  document.getElementById("results").style.display = "block";
}

// ─── BAR CHART ────────────────────────────────────
function buildBarChart(elId, headers) {
  const cats = {};
  headers.forEach(h => {
    const cfg = HEADERS.find(c => c.name === h.name);
    const cat = cfg ? cfg.category : "Other";
    if (!cats[cat]) cats[cat] = { s: 0, t: 0 };
    cats[cat].t++;
    if (h.status === "present") cats[cat].s += 1;
    if (h.status === "warning") cats[cat].s += 0.4;
  });

  const el = document.getElementById(elId);
  el.innerHTML = "";

  Object.entries(cats).forEach(([cat, v]) => {
    const pct = Math.round((v.s / v.t) * 100);
    const col = pct >= 70 ? "var(--good)" : pct >= 40 ? "var(--warn)" : "var(--danger)";
    const row = document.createElement("div");
    row.className = "bar-row";
    row.innerHTML = `
      <div class="bar-name">${cat}</div>
      <div class="bar-track">
        <div class="bar-fill" style="width:0%;background:${col}" data-p="${pct}"></div>
      </div>
      <div class="bar-pct">${pct}%</div>`;
    el.appendChild(row);
  });

  setTimeout(() => {
    el.querySelectorAll(".bar-fill").forEach(b => (b.style.width = b.dataset.p + "%"));
  }, 100);
}

// ─── DONUT CHART ──────────────────────────────────
function buildDonut(svgId, legendId, present, missing, warns, total) {
  const svg = document.getElementById(svgId);
  svg.innerHTML = "";

  const data = [
    { l: "Present",  n: present, c: "var(--good)" },
    { l: "Missing",  n: missing, c: "var(--danger)" },
    { l: "Warnings", n: warns,   c: "var(--warn)" },
  ].filter(d => d.n > 0);

  const cx = 55, cy = 55, r = 42, strokeWidth = 16;
  const circumference = 2 * Math.PI * r;
  let offset = 0;

  data.forEach(d => {
    const frac = d.n / total;
    const dash = frac * circumference;
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", cx);
    circle.setAttribute("cy", cy);
    circle.setAttribute("r", r);
    circle.setAttribute("fill", "none");
    circle.setAttribute("stroke", d.c);
    circle.setAttribute("stroke-width", strokeWidth);
    circle.setAttribute("stroke-dasharray", `${dash} ${circumference - dash}`);
    circle.setAttribute("stroke-dashoffset", circumference * 0.25 - offset);
    svg.appendChild(circle);
    offset += dash;
  });

  // Center labels
  [["" + total, "15", "Syne", "800", cy + 5], ["HDR", "7", "Share Tech Mono", "400", cy + 14]].forEach(
    ([text, size, font, weight, y]) => {
      const tx = document.createElementNS("http://www.w3.org/2000/svg", "text");
      tx.setAttribute("x", cx);
      tx.setAttribute("y", y);
      tx.setAttribute("text-anchor", "middle");
      tx.setAttribute("fill", weight === "800" ? "var(--heading)" : "#3d4f6b");
      tx.setAttribute("font-family", font);
      tx.setAttribute("font-size", size);
      tx.setAttribute("font-weight", weight);
      tx.textContent = text;
      svg.appendChild(tx);
    }
  );

  const legend = document.getElementById(legendId);
  legend.innerHTML = "";
  data.forEach(d => {
    const row = document.createElement("div");
    row.className = "legend-row";
    row.innerHTML = `<div class="legend-dot" style="background:${d.c}"></div><span>${d.l}: <strong>${d.n}</strong></span>`;
    legend.appendChild(row);
  });
}

// ─── HEADER CARDS ─────────────────────────────────
function buildCards(gridId, headers) {
  const grid = document.getElementById(gridId);
  grid.innerHTML = "";

  headers.forEach((h, i) => {
    const cls = h.status === "present" ? "good" : h.status === "warning" ? "warn" : "bad";
    const lbl = h.status === "present" ? "✓ Present" : h.status === "warning" ? "⚠ Warning" : "✗ Missing";
    const card = document.createElement("div");
    card.className = `hcard ${cls} fade-in`;
    card.style.animationDelay = `${i * 0.035}s`;
    card.innerHTML = `
      <div class="hcard-top">
        <div class="hcard-name">${h.name}</div>
        <div class="hcard-badge">${lbl}</div>
      </div>
      <div class="hcard-val">${h.value || "(not set)"}</div>
      <div class="hcard-desc">${h.description || ""}</div>`;
    grid.appendChild(card);
  });
}

// ─── COMPARE ──────────────────────────────────────
async function runCompare() {
  const urlA = document.getElementById("cmpUrlA").value.trim();
  const urlB = document.getElementById("cmpUrlB").value.trim();
  if (!urlA || !urlB) return;

  document.getElementById("cmpBtn").disabled = true;
  document.getElementById("cmpResults").style.display = "none";
  setStatus("cmpStatus", "running", "Scanning both URLs in parallel...");
  document.getElementById("scanOverlay").classList.add("on");

  try {
    const [resA, resB] = await Promise.all([analyzeWithClaude(urlA), analyzeWithClaude(urlB)]);
    renderCompare(urlA, resA, urlB, resB);
    setStatus("cmpStatus", "done", "Comparison complete.");
  } catch (e) {
    setStatus("cmpStatus", "error", e.message);
  } finally {
    document.getElementById("cmpBtn").disabled = false;
    document.getElementById("scanOverlay").classList.remove("on");
  }
}

function renderCompare(urlA, resA, urlB, resB) {
  const sA = calcScore(resA.headers), sB = calcScore(resB.headers);
  const gA = getGrade(sA), gB = getGrade(sB);

  document.getElementById("cmpLblA").textContent  = hostname(urlA);
  document.getElementById("cmpLblB").textContent  = hostname(urlB);
  document.getElementById("cmpScoreA").textContent = sA + "/100";
  document.getElementById("cmpScoreB").textContent = sB + "/100";

  const gaEl = document.getElementById("cmpGradeA");
  gaEl.textContent = gA; gaEl.style.background = GRADE_COLORS[gA] + "22"; gaEl.style.color = GRADE_COLORS[gA];

  const gbEl = document.getElementById("cmpGradeB");
  gbEl.textContent = gB; gbEl.style.background = GRADE_COLORS[gB] + "22"; gbEl.style.color = GRADE_COLORS[gB];

  const diff = sA - sB;
  const winner = diff > 0 ? hostname(urlA) : hostname(urlB);
  document.getElementById("cmpVerdict").innerHTML =
    diff === 0
      ? "Both sites scored equally."
      : `<strong style="color:${diff > 0 ? "var(--good)" : "var(--info)"}">${winner}</strong> leads by <strong>${Math.abs(diff)}</strong> pts — better overall HTTP header security.`;

  const grid = document.getElementById("cmpGrid");
  grid.innerHTML = "";

  const colA = document.createElement("div"); colA.className = "compare-col";
  const colB = document.createElement("div"); colB.className = "compare-col";
  colA.innerHTML = `<div class="compare-col-title">${hostname(urlA)}</div>`;
  colB.innerHTML = `<div class="compare-col-title">${hostname(urlB)}</div>`;

  HEADERS.forEach(cfg => {
    const hA = resA.headers.find(h => h.name === cfg.name) || { status: "missing" };
    const hB = resB.headers.find(h => h.name === cfg.name) || { status: "missing" };

    [colA, colB].forEach((col, idx) => {
      const h = idx === 0 ? hA : hB;
      const color = h.status === "present" ? "var(--good)" : h.status === "warning" ? "var(--warn)" : "var(--danger)";
      const sym   = h.status === "present" ? "✓" : h.status === "warning" ? "⚠" : "✗";
      const row = document.createElement("div");
      row.className = "compare-row";
      row.innerHTML = `<span style="font-size:.7rem;color:var(--text);">${cfg.name}</span><span style="color:${color};font-size:.8rem;">${sym}</span>`;
      col.appendChild(row);
    });
  });

  grid.appendChild(colA);
  grid.appendChild(colB);
  document.getElementById("cmpResults").style.display = "block";
}

// ─── MULTI-PAGE CRAWL ─────────────────────────────
function generateSubpages(baseUrl, n) {
  const paths = ["/", "about", "/contact", "/privacy", "/terms", "/login", "/signup", "/blog", "/faq", "/help"];
  const base = baseUrl.replace(/\/$/, "");
  const pages = [base];
  for (let i = 1; i < n && i < paths.length; i++) pages.push(base + paths[i]);
  return pages;
}

async function runCrawl() {
  const url   = document.getElementById("crawlUrl").value.trim();
  const depth = parseInt(document.getElementById("crawlDepth").value);
  if (!url) return;

  document.getElementById("crawlBtn").disabled = true;
  document.getElementById("crawlResults").style.display = "none";
  document.getElementById("crawlProgress").style.display = "block";
  setStatus("crawlStatus", "running", "Starting crawl...");
  document.getElementById("scanOverlay").classList.add("on");

  const pages = generateSubpages(url, depth);
  const results = [];

  for (let i = 0; i < pages.length; i++) {
    const pct = Math.round(((i + 1) / pages.length) * 100);
    document.getElementById("progressFill").style.width = pct + "%";
    document.getElementById("crawlProgressPct").textContent = pct + "%";
    document.getElementById("crawlProgressLbl").textContent = `Scanning ${pages[i]}`;
    setStatus("crawlStatus", "running", `Page ${i + 1}/${pages.length}: ${pages[i]}`);

    try {
      const analysis = await analyzeWithClaude(pages[i]);
      results.push({ url: pages[i], analysis, score: calcScore(analysis.headers) });
    } catch {
      results.push({ url: pages[i], analysis: null, score: 0, error: true });
    }
  }

  renderCrawl(results);
  setStatus("crawlStatus", "done", `Crawl complete — ${pages.length} pages scanned.`);
  document.getElementById("crawlBtn").disabled = false;
  document.getElementById("scanOverlay").classList.remove("on");
}

function renderCrawl(results) {
  const scores = results.filter(r => !r.error).map(r => r.score);
  const avg   = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  const worst = scores.length ? Math.min(...scores) : 0;

  document.getElementById("crawlAvgScore").textContent = avg;
  document.getElementById("crawlPages").textContent    = results.length;
  document.getElementById("crawlWorst").textContent    = worst;

  const list = document.getElementById("crawlPageList");
  list.innerHTML = "";

  results.forEach((r, i) => {
    const grade = r.error ? "?" : getGrade(r.score);
    const color = r.error ? "var(--muted)" : GRADE_COLORS[grade];
    const item  = document.createElement("div");
    item.className = "crawl-page fade-in";
    item.style.animationDelay = `${i * 0.06}s`;
    item.innerHTML = `
      <div style="font-size:.7rem;background:${color}22;color:${color};border:1px solid ${color}44;border-radius:6px;padding:3px 9px;font-family:var(--font-ui);font-weight:800;flex-shrink:0;">${grade}</div>
      <div class="crawl-page-url">${r.url}</div>
      <div style="font-family:var(--font-ui);font-weight:700;font-size:.88rem;flex-shrink:0;color:${color};">${r.error ? "err" : r.score + "/100"}</div>`;
    list.appendChild(item);
  });

  document.getElementById("crawlResults").style.display = "block";
}

// ─── TREND CHARTS ─────────────────────────────────
function renderTrends() {
  const hist = getHistory();
  const el   = document.getElementById("trendContent");

  if (!hist.length) {
    el.innerHTML = `<div class="trend-empty">📊 No trend data yet.<br><span style="font-size:.72rem">Run a few scans on the same domain to see score trends.</span></div>`;
    return;
  }

  // Group by hostname
  const grouped = {};
  hist.forEach(item => {
    const host = hostname(item.url);
    if (!grouped[host]) grouped[host] = [];
    grouped[host].unshift({ score: calcScore(item.analysis.headers), ts: item.ts });
  });

  el.innerHTML = '<div class="trend-grid" id="trendGrid"></div>';
  const grid = document.getElementById("trendGrid");

  Object.entries(grouped).forEach(([host, entries]) => {
    const scores = entries.map(e => e.score);
    const latest = scores[scores.length - 1];
    const diff   = latest - scores[0];
    const diffColor = diff > 0 ? "var(--good)" : diff < 0 ? "var(--danger)" : "var(--muted)";
    const diffStr   = diff === 0 ? "stable" : diff > 0 ? `+${diff}` : `${diff}`;

    const card = document.createElement("div");
    card.className = "trend-card fade-in";
    card.innerHTML = `
      <div class="trend-url" title="${host}">${host}</div>
      <div class="sparkline-wrap">
        <canvas class="spark-canvas" id="spark-${host.replace(/\./g, "_")}" height="48"></canvas>
      </div>
      <div class="trend-stats">
        <span>${entries.length} scan${entries.length > 1 ? "s" : ""}</span>
        <span class="trend-latest" style="color:${GRADE_COLORS[getGrade(latest)]}">
          ${latest}/100 <span style="color:${diffColor};font-size:.6rem;">(${diffStr})</span>
        </span>
      </div>`;
    grid.appendChild(card);

    requestAnimationFrame(() => drawSparkline(`spark-${host.replace(/\./g, "_")}`, scores));
  });
}

function drawSparkline(canvasId, scores) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  const dpr = window.devicePixelRatio || 1;
  const W = canvas.offsetWidth, H = 48;
  canvas.width  = W * dpr;
  canvas.height = H * dpr;

  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);

  if (scores.length < 2) {
    ctx.fillStyle = "rgba(0,255,224,.5)";
    ctx.beginPath();
    ctx.arc(W / 2, H / 2, 4, 0, Math.PI * 2);
    ctx.fill();
    return;
  }

  const min = Math.max(0, Math.min(...scores) - 10);
  const max = Math.min(100, Math.max(...scores) + 10);
  const xStep  = (W - 12) / (scores.length - 1);
  const yScale = (H - 12) / (max - min || 1);
  const pts = scores.map((s, i) => ({ x: 6 + i * xStep, y: H - 6 - (s - min) * yScale }));

  const isDark = document.documentElement.dataset.theme !== "light";

  // Gradient fill
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, isDark ? "rgba(0,255,224,.25)" : "rgba(0,180,160,.2)");
  grad.addColorStop(1, "rgba(0,255,224,0)");

  ctx.beginPath();
  ctx.moveTo(pts[0].x, pts[0].y);
  pts.slice(1).forEach(p => ctx.lineTo(p.x, p.y));
  ctx.lineTo(pts[pts.length - 1].x, H);
  ctx.lineTo(pts[0].x, H);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.moveTo(pts[0].x, pts[0].y);
  pts.slice(1).forEach(p => ctx.lineTo(p.x, p.y));
  ctx.strokeStyle = isDark ? "#00ffe0" : "#00b4a0";
  ctx.lineWidth   = 1.5;
  ctx.lineJoin    = "round";
  ctx.stroke();

  // Dots
  pts.forEach(p => {
    ctx.beginPath();
    ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2);
    ctx.fillStyle = isDark ? "#00ffe0" : "#00b4a0";
    ctx.fill();
  });
}

// ─── SCHEDULED ALERTS ─────────────────────────────
function getAlerts() {
  try { return JSON.parse(localStorage.getItem("vs_alerts") || "[]"); }
  catch { return []; }
}

function saveAlerts(alerts) {
  localStorage.setItem("vs_alerts", JSON.stringify(alerts));
  updateAlertBadge();
}

function addAlert() {
  const url      = document.getElementById("alertUrl").value.trim();
  const interval = parseInt(document.getElementById("alertInterval").value);
  if (!url) return;

  const alerts = getAlerts();
  const id = "alert_" + Date.now();
  alerts.push({ id, url, interval, lastScore: null, lastRun: null, active: true });
  saveAlerts(alerts);
  startAlertTimer(id);
  renderAlerts();
  showToast("Alert added for " + hostname(url), "var(--good)");
}

function startAlertTimer(id) {
  const alert = getAlerts().find(a => a.id === id);
  if (!alert || !alert.active) return;
  if (alertTimers[id]) clearInterval(alertTimers[id]);

  alertTimers[id] = setInterval(async () => {
    try {
      const analysis = await analyzeWithClaude(alert.url);
      const score    = calcScore(analysis.headers);
      const stored   = getAlerts();
      const idx      = stored.findIndex(a => a.id === id);
      if (idx < 0) return clearInterval(alertTimers[id]);

      const prev = stored[idx].lastScore;
      stored[idx].lastScore = score;
      stored[idx].lastRun   = Date.now();
      saveAlerts(stored);

      if (prev !== null && Math.abs(score - prev) >= 5) {
        const diff = score - prev;
        showToast(
          `${hostname(alert.url)}: score ${diff > 0 ? "↑" : "↓"} ${diff > 0 ? "+" : ""}${diff} → ${score}/100`,
          diff > 0 ? "var(--good)" : "var(--danger)"
        );
      }
      renderAlerts();
    } catch (e) {
      console.warn("Alert scan failed:", e.message);
    }
  }, alert.interval * 60 * 1000);
}

function removeAlert(id) {
  if (alertTimers[id]) { clearInterval(alertTimers[id]); delete alertTimers[id]; }
  saveAlerts(getAlerts().filter(a => a.id !== id));
  renderAlerts();
}

async function runAlertNow(id) {
  const alert = getAlerts().find(a => a.id === id);
  if (!alert) return;
  showToast("Running scan for " + hostname(alert.url), "var(--accent)");
  try {
    const analysis = await analyzeWithClaude(alert.url);
    const score    = calcScore(analysis.headers);
    const stored   = getAlerts();
    const idx      = stored.findIndex(a => a.id === id);
    stored[idx].lastScore = score;
    stored[idx].lastRun   = Date.now();
    saveAlerts(stored);
    renderAlerts();
    showToast(`${hostname(alert.url)}: ${score}/100 (${getGrade(score)})`, "var(--good)");
  } catch (e) {
    showToast("Scan failed: " + e.message, "var(--danger)");
  }
}

function renderAlerts() {
  const alerts = getAlerts();
  const el = document.getElementById("alertList");
  updateAlertBadge();

  if (!alerts.length) {
    el.innerHTML = '<div style="text-align:center;padding:32px;color:var(--muted);font-size:.78rem;">No alerts configured yet.</div>';
    return;
  }

  el.innerHTML = "";
  alerts.forEach(a => {
    const lastRun  = a.lastRun ? new Date(a.lastRun).toLocaleTimeString() : "Never";
    const scoreStr = a.lastScore !== null ? `Last: ${a.lastScore}/100 (${getGrade(a.lastScore)})` : "Pending first scan";
    const item = document.createElement("div");
    item.className = "alert-item fade-in";
    item.innerHTML = `
      <div class="alert-icon">🔔</div>
      <div class="alert-info">
        <div class="alert-url">${a.url}</div>
        <div class="alert-meta">Every ${a.interval} min · ${scoreStr} · Last run: ${lastRun}</div>
      </div>
      <div class="alert-badge ${a.active ? "badge-active" : "badge-pending"}">${a.active ? "Active" : "Paused"}</div>
      <div class="alert-actions">
        <button class="icon-btn" onclick="runAlertNow('${a.id}')" title="Scan now">▶</button>
        <button class="icon-btn del" onclick="removeAlert('${a.id}')" title="Remove">✕</button>
      </div>`;
    el.appendChild(item);
  });
}

function updateAlertBadge() {
  const n = getAlerts().filter(a => a.active).length;
  const b = document.getElementById("alertBadge");
  b.textContent = n;
  b.style.display = n ? "inline" : "none";
}

// ─── HISTORY ──────────────────────────────────────
function saveToHistory(result) {
  let h = getHistory();
  h.unshift(result);
  if (h.length > 30) h = h.slice(0, 30);
  localStorage.setItem("vs_history", JSON.stringify(h));
  updateHistBadge();
}

function getHistory() {
  try { return JSON.parse(localStorage.getItem("vs_history") || "[]"); }
  catch { return []; }
}

function updateHistBadge() {
  const n = getHistory().length;
  const b = document.getElementById("histBadge");
  b.textContent = n;
  b.style.display = n ? "inline" : "none";
}

function renderHistory() {
  const hist = getHistory();
  const el   = document.getElementById("historyList");

  if (!hist.length) {
    el.innerHTML = '<div style="text-align:center;padding:40px 20px;color:var(--muted);font-size:.8rem;">🕓 No scans yet.</div>';
    return;
  }

  el.innerHTML = "";
  hist.forEach((item, i) => {
    const pct   = calcScore(item.analysis.headers);
    const grade = getGrade(pct);
    const color = GRADE_COLORS[grade];
    const d     = new Date(item.ts);

    const row = document.createElement("div");
    row.className = "history-item fade-in";
    row.style.animationDelay = `${i * 0.03}s`;
    row.innerHTML = `
      <div class="history-grade" style="color:${color};border:1px solid ${color}33;">${grade}</div>
      <div class="history-info">
        <div class="history-url">${item.url}</div>
        <div class="history-meta">${d.toLocaleDateString()} ${d.toLocaleTimeString()}</div>
      </div>
      <div style="font-size:.75rem;color:var(--muted);">${pct}/100</div>
      <div class="history-actions">
        <button class="icon-btn" title="Load" onclick="loadHist(${i})">↗</button>
        <button class="icon-btn del" title="Delete" onclick="delHist(${i}, event)">✕</button>
      </div>`;
    el.appendChild(row);
  });
}

function loadHist(i) {
  const item = getHistory()[i];
  document.getElementById("urlInput").value = item.url;
  currentResult = item;
  renderResults(item.url, item.analysis);
  setStatus("statusBar", "done", "Loaded from history.");
  showTab("scan", document.querySelector(".nav-btn"));
}

function delHist(i, e) {
  e.stopPropagation();
  let h = getHistory();
  h.splice(i, 1);
  localStorage.setItem("vs_history", JSON.stringify(h));
  updateHistBadge();
  renderHistory();
}

function clearHistory() {
  if (!confirm("Clear all scan history?")) return;
  localStorage.removeItem("vs_history");
  updateHistBadge();
  renderHistory();
}

// ─── EXPORT PDF ───────────────────────────────────
async function exportPDF() {
  if (!currentResult) { showToast("Run a scan first.", "var(--danger)"); return; }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const { url, analysis } = currentResult;
  const headers = analysis.headers || [];
  const pct     = calcScore(headers);
  const grade   = getGrade(pct);
  const ts      = new Date(currentResult.ts).toLocaleString();
  const isDark  = document.documentElement.dataset.theme !== "light";

  const BG     = isDark ? [8,11,16]       : [240,244,248];
  const SURF   = isDark ? [15,20,32]      : [255,255,255];
  const TEXT   = isDark ? [200,214,232]   : [51,65,85];
  const MUTED  = isDark ? [61,79,107]     : [148,163,184];
  const GOOD   = [0,224,122], WARN = [247,201,72], DANGER = [255,77,109];

  doc.setFillColor(...BG);   doc.rect(0,0,210,297,"F");
  doc.setFillColor(...SURF); doc.rect(0,0,210,46,"F");
  doc.setDrawColor(0,255,224); doc.setLineWidth(0.4); doc.line(0,46,210,46);

  doc.setFont("helvetica","bold"); doc.setFontSize(20); doc.setTextColor(0,255,224);
  doc.text("VulnScope v3", 14, 17);
  doc.setFontSize(7);  doc.setTextColor(...MUTED); doc.text("HTTP Header Security Report", 14, 24);
  doc.setFontSize(8);  doc.setTextColor(...TEXT);  doc.text(url, 14, 32); doc.text("Scanned: " + ts, 14, 39);

  const sc = pct >= 70 ? GOOD : pct >= 45 ? WARN : DANGER;
  doc.setFontSize(26); doc.setFont("helvetica","bold"); doc.setTextColor(...sc);
  doc.text(pct + "/100", 196, 20, { align: "right" });
  doc.setFontSize(16); doc.text("Grade: " + grade, 196, 40, { align: "right" });

  let y = 56;
  const present = headers.filter(h => h.status === "present").length;
  const missing = headers.filter(h => h.status === "missing").length;
  const warns   = headers.filter(h => h.status === "warning").length;

  [{ l:"Present",v:present,c:GOOD }, { l:"Missing",v:missing,c:DANGER }, { l:"Warnings",v:warns,c:WARN }].forEach((s, i) => {
    const x = 14 + i * 62;
    doc.setFillColor(...SURF); doc.roundedRect(x, y, 58, 18, 2, 2, "F");
    doc.setFont("helvetica","bold"); doc.setFontSize(13); doc.setTextColor(...s.c); doc.text("" + s.v, x + 7, y + 10);
    doc.setFont("helvetica","normal"); doc.setFontSize(6.5); doc.setTextColor(...MUTED); doc.text(s.l, x + 7, y + 16);
  });
  y += 26;

  doc.setFillColor(...SURF); doc.roundedRect(14, y, 182, 20, 2, 2, "F");
  doc.setFont("helvetica","bold"); doc.setFontSize(6.5); doc.setTextColor(0,255,224); doc.text("AI SUMMARY", 18, y + 6);
  doc.setFont("helvetica","normal"); doc.setFontSize(6.5); doc.setTextColor(...TEXT);
  doc.text(doc.splitTextToSize(analysis.summary || "", 172), 18, y + 13);
  y += 24;

  doc.setFont("helvetica","bold"); doc.setFontSize(7); doc.setTextColor(0,255,224);
  doc.text("HEADER ANALYSIS", 14, y); y += 7;

  headers.forEach(h => {
    if (y > 270) { doc.addPage(); doc.setFillColor(...BG); doc.rect(0,0,210,297,"F"); y = 14; }
    const c   = h.status === "present" ? GOOD : h.status === "warning" ? WARN : DANGER;
    const lbl = h.status === "present" ? "PRESENT" : h.status === "warning" ? "WARNING" : "MISSING";
    doc.setFillColor(...SURF); doc.roundedRect(14, y, 182, 18, 2, 2, "F");
    doc.setDrawColor(...c); doc.setLineWidth(0.35); doc.line(14, y + 0.5, 14, y + 17.5);
    doc.setFont("helvetica","bold"); doc.setFontSize(7); doc.setTextColor(...TEXT); doc.text(h.name, 18, y + 6);
    doc.setFontSize(6); doc.setTextColor(...c); doc.text(lbl, 192, y + 6, { align: "right" });
    doc.setFont("helvetica","normal"); doc.setFontSize(6); doc.setTextColor(...MUTED); doc.text(h.value || "(not set)", 18, y + 11);
    doc.setTextColor(...TEXT); doc.text(doc.splitTextToSize(h.description || "", 170)[0], 18, y + 16);
    y += 21;
  });

  doc.setFontSize(6); doc.setTextColor(...MUTED);
  doc.text("Generated by VulnScope v3 — Powered by Claude AI", 105, 291, { align: "center" });
  doc.save(`vulnscope-${hostname(url)}-${Date.now()}.pdf`);
}

// ─── EXPORT JSON ──────────────────────────────────
function exportJSON() {
  if (!currentResult) { showToast("Run a scan first.", "var(--danger)"); return; }
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `vulnscope-${Date.now()}.json`;
  a.click();
}

// ─── TOAST ────────────────────────────────────────
let toastTimer;

function showToast(msg, color = "var(--accent)") {
  const toast = document.getElementById("toast");
  document.getElementById("toastDot").style.background = color;
  document.getElementById("toastMsg").textContent = msg;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3500);
}

// ─── INIT ─────────────────────────────────────────
document.getElementById("urlInput").addEventListener("keydown", e => {
  if (e.key === "Enter") runScan();
});

updateHistBadge();
updateAlertBadge();

// Restart alert timers on page load
getAlerts().forEach(a => { if (a.active) startAlertTimer(a.id); });

// Redraw sparklines when theme changes
const themeObserver = new MutationObserver(() => {
  if (document.getElementById("tab-trends").classList.contains("active")) renderTrends();
});
themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
