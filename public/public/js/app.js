// ============== State ==============
const TEMPLATES = {
  'Web App': { methodology: 'OWASP Testing Guide v4.2 and OWASP Top 10 (2021) — manual and automated testing of authentication, session management, input validation, business logic, and API endpoints.' },
  'Network': { methodology: 'PTES / NIST SP 800-115 — external and internal network enumeration, service fingerprinting, vulnerability scanning, and manual exploitation of identified hosts.' },
  'Cloud': { methodology: 'CIS Cloud Benchmarks and MITRE ATT&CK Cloud Matrix — IAM misconfiguration review, storage exposure checks, and workload security assessment across the cloud environment.' },
  'Mobile': { methodology: 'OWASP MASVS / MASTG — static and dynamic analysis of the mobile binary, API traffic inspection, local storage review, and platform-specific security controls.' }
};

let state = {
  template: 'Web App',
  cvssVersion: '3.1',
  meta: { title: '', client: '', date: '', scope: '', methodology: TEMPLATES['Web App'].methodology, executiveSummary: '' },
  findings: [],
  projectId: null
};

let licenseKey = localStorage.getItem('pentscribe_license') || null;
let openFindingId = null;

// ============== Helpers ==============
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);
const uid = () => Math.random().toString(36).slice(2, 10);

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2600);
}

function apiHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (licenseKey) h['x-license-key'] = licenseKey;
  return h;
}

// ============== Findings model ==============
function newFinding() {
  return {
    id: uid(),
    title: 'New Finding',
    severity: 'Medium',
    status: 'Open',
    description: '', stepsToReproduce: '', evidence: '', remediation: '',
    cvss31: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'L' },
    cvss40: { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'L', VI: 'L', VA: 'L', SC: 'N', SI: 'N', SA: 'N' }
  };
}

function findingScore(f) {
  return state.cvssVersion === '3.1' ? calcCVSS31(f.cvss31) : calcCVSS40Approx(f.cvss40);
}
function findingVector(f) {
  return state.cvssVersion === '3.1' ? vectorString31(f.cvss31) : vectorString40(f.cvss40);
}

// ============== Rendering ==============
function renderTemplateGrid() {
  $$('.template-card').forEach(el => {
    el.classList.toggle('active', el.dataset.template === state.template);
  });
}

function renderCvssToggle() {
  $$('#cvssToggle .toggle-btn').forEach(el => {
    el.classList.toggle('active', el.dataset.v === state.cvssVersion);
  });
  renderFindings(); // rescoring depends on version
}

function severityColor(sev) {
  return { Critical: 'var(--crit)', High: 'var(--high)', Medium: 'var(--med)', Low: 'var(--low)', Informational: 'var(--none-sev)' }[sev] || 'var(--none-sev)';
}

function renderSeverityBar() {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  state.findings.forEach(f => counts[f.severity]++);
  const total = state.findings.length || 1;
  const bar = $('#severityBar');
  bar.innerHTML = Object.entries(counts).map(([sev, c]) =>
    c ? `<span style="width:${(c / total) * 100}%; background:${severityColor(sev)}"></span>` : ''
  ).join('');
  $('#findingsCount').textContent = `(${state.findings.length})`;
}

function cvssFieldsHTML(f) {
  if (state.cvssVersion === '3.1') {
    const m = f.cvss31;
    const opt = (group, key, options) => options.map(o =>
      `<option value="${o}" ${m[key] === o ? 'selected' : ''}>${o}</option>`).join('');
    return `
      <div class="grid-2">
        <div class="field"><label class="field-label">Attack Vector</label>
          <select data-cvss="AV">${opt('AV','AV',['N','A','L','P'])}</select></div>
        <div class="field"><label class="field-label">Attack Complexity</label>
          <select data-cvss="AC">${opt('AC','AC',['L','H'])}</select></div>
        <div class="field"><label class="field-label">Privileges Required</label>
          <select data-cvss="PR">${opt('PR','PR',['N','L','H'])}</select></div>
        <div class="field"><label class="field-label">User Interaction</label>
          <select data-cvss="UI">${opt('UI','UI',['N','R'])}</select></div>
        <div class="field"><label class="field-label">Scope</label>
          <select data-cvss="S">${opt('S','S',['U','C'])}</select></div>
        <div class="field"><label class="field-label">Confidentiality</label>
          <select data-cvss="C">${opt('C','C',['N','L','H'])}</select></div>
        <div class="field"><label class="field-label">Integrity</label>
          <select data-cvss="I">${opt('I','I',['N','L','H'])}</select></div>
        <div class="field"><label class="field-label">Availability</label>
          <select data-cvss="A">${opt('A','A',['N','L','H'])}</select></div>
      </div>`;
  } else {
    const m = f.cvss40;
    const opt = (key, options) => options.map(o =>
      `<option value="${o}" ${m[key] === o ? 'selected' : ''}>${o}</option>`).join('');
    return `
      <div class="grid-2">
        <div class="field"><label class="field-label">Attack Vector</label><select data-cvss4="AV">${opt('AV',['N','A','L','P'])}</select></div>
        <div class="field"><label class="field-label">Attack Complexity</label><select data-cvss4="AC">${opt('AC',['L','H'])}</select></div>
        <div class="field"><label class="field-label">Attack Requirements</label><select data-cvss4="AT">${opt('AT',['N','P'])}</select></div>
        <div class="field"><label class="field-label">Privileges Required</label><select data-cvss4="PR">${opt('PR',['N','L','H'])}</select></div>
        <div class="field"><label class="field-label">User Interaction</label><select data-cvss4="UI">${opt('UI',['N','P','A'])}</select></div>
        <div class="field"><label class="field-label">Vuln Confidentiality</label><select data-cvss4="VC">${opt('VC',['N','L','H'])}</select></div>
        <div class="field"><label class="field-label">Vuln Integrity</label><select data-cvss4="VI">${opt('VI',['N','L','H'])}</select></div>
        <div class="field"><label class="field-label">Vuln Availability</label><select data-cvss4="VA">${opt('VA',['N','L','H'])}</select></div>
        <div class="field"><label class="field-label">Subseq. Confidentiality</label><select data-cvss4="SC">${opt('SC',['N','L','H'])}</select></div>
        <div class="field"><label class="field-label">Subseq. Integrity</label><select data-cvss4="SI">${opt('SI',['N','L','H'])}</select></div>
        <div class="field"><label class="field-label">Subseq. Availability</label><select data-cvss4="SA">${opt('SA',['N','L','H'])}</select></div>
      </div>`;
  }
}

function findingCardHTML(f, index) {
  const score = findingScore(f);
  const sev = score === 0 && f.severity === 'Informational' ? 'Informational' : severityFromScore(score);
  if (f.severity !== sev) f.severity = sev; // keep severity synced to computed score
  const open = openFindingId === f.id;
  return `
  <div class="finding-card" style="animation-delay:${index * 0.04}s" data-id="${f.id}">
    <div class="finding-head" data-toggle="${f.id}">
      <span class="sev-chip sev-${f.severity}">${f.severity}</span>
      <input class="finding-title-input" data-field="title" value="${escapeAttr(f.title)}" placeholder="Finding title">
      <span class="cvss-badge">CVSS ${state.cvssVersion}: ${score.toFixed(1)}</span>
      <select data-field="status" style="width:auto; padding:6px 8px; font-size:12px;">
        ${['Open','Remediated','Accepted Risk','False Positive'].map(s => `<option ${f.status===s?'selected':''}>${s}</option>`).join('')}
      </select>
      <span class="remove-finding" data-remove="${f.id}">✕</span>
    </div>
    <div class="finding-body ${open ? 'open' : ''}">
      <div class="section-label">CVSS ${state.cvssVersion} Vector</div>
      ${cvssFieldsHTML(f)}
      <div class="vector-string">${findingVector(f)}</div>

      <div class="section-label">Description <span class="ai-assist-btn" data-ai="description" data-fid="${f.id}">✨ AI Draft</span></div>
      <textarea data-field="description" placeholder="Technical description of the vulnerability...">${f.description}</textarea>

      <div class="section-label">Steps to Reproduce</div>
      <textarea data-field="stepsToReproduce" placeholder="1. Navigate to...&#10;2. Submit payload...">${f.stepsToReproduce}</textarea>

      <div class="section-label">Evidence</div>
      <textarea data-field="evidence" placeholder="Request/response snippets, screenshots reference...">${f.evidence}</textarea>

      <div class="section-label">Remediation <span class="ai-assist-btn" data-ai="remediation" data-fid="${f.id}">✨ AI Draft</span></div>
      <textarea data-field="remediation" placeholder="Recommended fix...">${f.remediation}</textarea>
    </div>
  </div>`;
}

function escapeAttr(s) { return (s || '').replace(/"/g, '&quot;'); }
function escapeHtml(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,'<br>');
}

function renderFindings() {
  $('#findingsList').innerHTML = state.findings.map((f, i) => findingCardHTML(f, i)).join('');
  renderSeverityBar();
  renderPreview();
}

function renderPreview() {
  const m = state.meta;
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  state.findings.forEach(f => counts[f.severity]++);

  const donut = donutSVG(counts);
  const legend = Object.entries(counts).map(([sev, c]) =>
    `<div><span style="background:${severityColor(sev)}"></span>${sev}: ${c}</div>`).join('');

  const findingsHTML = state.findings.map((f, i) => `
    <div class="preview-finding">
      <strong>${i + 1}. ${escapeHtml(f.title) || 'Untitled finding'}</strong>
      <span class="preview-sev-tag" style="background:${severityColor(f.severity)}22; color:${severityColor(f.severity)}">${f.severity} · CVSS ${findingScore(f).toFixed(1)}</span>
      <p style="margin:6px 0 0; color:#b8b9c6;">${escapeHtml(f.description) || '<em>No description yet.</em>'}</p>
    </div>
  `).join('') || '<p style="color:var(--text-faint)">No findings added yet.</p>';

  $('#previewDoc').innerHTML = `
    <h1>${escapeHtml(m.title) || 'Untitled Report'}</h1>
    <div class="preview-meta">${state.template} Assessment &nbsp;·&nbsp; ${escapeHtml(m.client) || 'Client name'} &nbsp;·&nbsp; ${m.date || 'Date'}</div>
    <h2>Executive Summary</h2>
    <p>${escapeHtml(m.executiveSummary) || '<em>Not written yet.</em>'}</p>
    <h2>Scope</h2>
    <p>${escapeHtml(m.scope) || '<em>Not defined yet.</em>'}</p>
    <h2>Findings Overview</h2>
    <div class="donut-wrap">${donut}<div class="legend">${legend}</div></div>
    <h2>Detailed Findings</h2>
    ${findingsHTML}
  `;
}

function donutSVG(counts) {
  const colors = { Critical: '#ff2d55', High: '#ff6b3d', Medium: '#ffc857', Low: '#5fb0ff', Informational: '#7a7d90' };
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) return `<svg width="90" height="90" viewBox="0 0 42 42"><circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#2a2a35" stroke-width="5"/></svg>`;
  let offset = 0;
  const circumference = 2 * Math.PI * 15.9;
  const circles = Object.entries(counts).filter(([, c]) => c > 0).map(([sev, c]) => {
    const pct = c / total;
    const dash = pct * circumference;
    const circle = `<circle cx="21" cy="21" r="15.9" fill="transparent" stroke="${colors[sev]}" stroke-width="5" stroke-dasharray="${dash} ${circumference - dash}" stroke-dashoffset="${-offset}" transform="rotate(-90 21 21)"/>`;
    offset += dash;
    return circle;
  }).join('');
  return `<svg width="90" height="90" viewBox="0 0 42 42">${circles}<text x="21" y="24" text-anchor="middle" font-size="9" fill="#eceef2" font-family="JetBrains Mono">${total}</text></svg>`;
}

// ============== Events ==============
function bindStaticEvents() {
  $$('.template-card').forEach(el => el.addEventListener('click', () => {
    state.template = el.dataset.template;
    state.meta.methodology = TEMPLATES[state.template].methodology;
    $('#methodology').value = state.meta.methodology;
    renderTemplateGrid();
    renderPreview();
  }));

  $$('#cvssToggle .toggle-btn').forEach(el => el.addEventListener('click', () => {
    state.cvssVersion = el.dataset.v;
    renderCvssToggle();
  }));

  ['reportTitle','client','reportDate','scope','methodology','executiveSummary'].forEach(id => {
    $('#' + id).addEventListener('input', (e) => {
      const map = { reportTitle: 'title', reportDate: 'date' };
      const key = map[id] || id;
      state.meta[key] = e.target.value;
      renderPreview();
    });
  });

  $('#addFindingBtn').addEventListener('click', () => {
    const f = newFinding();
    state.findings.push(f);
    openFindingId = f.id;
    renderFindings();
  });

  $('#findingsList').addEventListener('click', (e) => {
    const toggleId = e.target.closest('[data-toggle]')?.dataset.toggle;
    if (toggleId && !e.target.matches('input,select,textarea')) {
      openFindingId = openFindingId === toggleId ? null : toggleId;
      renderFindings();
      return;
    }
    const removeId = e.target.dataset.remove;
    if (removeId) {
      state.findings = state.findings.filter(f => f.id !== removeId);
      renderFindings();
      return;
    }
    if (e.target.dataset.ai) {
      runAiAssist(e.target.dataset.ai, e.target.dataset.fid);
    }
  });

  $('#findingsList').addEventListener('input', (e) => {
    const card = e.target.closest('.finding-card');
    if (!card) return;
    const f = state.findings.find(x => x.id === card.dataset.id);
    if (!f) return;
    if (e.target.dataset.field) { f[e.target.dataset.field] = e.target.value; }
    if (e.target.dataset.cvss) { f.cvss31[e.target.dataset.cvss] = e.target.value; }
    if (e.target.dataset.cvss4) { f.cvss40[e.target.dataset.cvss4] = e.target.value; }
    renderSeverityBar();
    renderPreview();
    // refresh just the badges without collapsing the open card
    const badge = card.querySelector('.cvss-badge');
    if (badge) badge.textContent = `CVSS ${state.cvssVersion}: ${findingScore(f).toFixed(1)}`;
    const vec = card.querySelector('.vector-string');
    if (vec) vec.textContent = findingVector(f);
    const chip = card.querySelector('.sev-chip');
    if (chip) { chip.className = `sev-chip sev-${f.severity}`; chip.textContent = f.severity; }
  });

  $('#exportMd').addEventListener('click', () => exportReport('markdown'));
  $('#exportDocx').addEventListener('click', () => exportReport('docx'));
  $('#exportPdf').addEventListener('click', () => window.print());

  $('#saveBtn').addEventListener('click', saveProject);
  $('#loadBtn').addEventListener('click', loadProjectPrompt);

  $('#upgradeBtn').addEventListener('click', () => showModal(true));
  $('#closeModal').addEventListener('click', () => showModal(false));
  $('#checkoutBtn').addEventListener('click', startCheckout);
}

function showModal(show) { $('#paywallModal').classList.toggle('show', show); }

// ============== AI Assist ==============
async function runAiAssist(mode, fid) {
  const f = fid ? state.findings.find(x => x.id === fid) : null;
  const context = f
    ? { title: f.title, template: state.template, severity: f.severity, notes: f.description || f.stepsToReproduce }
    : { template: state.template, scope: state.meta.scope, findingsCount: state.findings.length, severityBreakdown: countBySeverity() };
  const targetMode = fid ? mode : 'executive_summary';

  toast('Drafting with AI…');
  try {
    const res = await fetch('/api/ai-assist', {
      method: 'POST', headers: apiHeaders(),
      body: JSON.stringify({ mode: targetMode, context })
    });
    if (res.status === 402) { showModal(true); return; }
    const data = await res.json();
    if (data.error === 'ai_not_configured') { toast('AI assist needs ANTHROPIC_API_KEY set on the server.'); return; }
    if (data.text) {
      if (f) { f[mode === 'description' ? 'description' : 'remediation'] = data.text; renderFindings(); openFindingId = f.id; renderFindings(); }
      else { state.meta.executiveSummary = data.text; $('#executiveSummary').value = data.text; renderPreview(); }
      toast('AI draft inserted ✨');
    }
  } catch (err) { toast('AI assist failed — check server logs.'); }
}

function countBySeverity() {
  const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  state.findings.forEach(f => c[f.severity]++);
  return c;
}

// Wire the exec-summary AI button separately (no finding id)
document.addEventListener('DOMContentLoaded', () => {
  $('#aiExecSummary')?.addEventListener('click', () => runAiAssist('executive_summary', null));
});

// ============== Export ==============
async function exportReport(type) {
  const payload = { meta: { ...state.meta, template: state.template, cvssVersion: state.cvssVersion }, findings: state.findings.map(f => ({ ...f, cvssScore: findingScore(f), cvssVector: findingVector(f) })) };
  try {
    const res = await fetch(`/api/export/${type}`, { method: 'POST', headers: apiHeaders(), body: JSON.stringify(payload) });
    if (res.status === 402) { showModal(true); return; }
    if (!res.ok) { toast('Export failed.'); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(state.meta.title || 'report').replace(/\s+/g, '_')}.${type === 'docx' ? 'docx' : 'md'}`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    toast('Export ready ✅');
  } catch (err) { toast('Export failed — server unreachable.'); }
}

// ============== Save / Load ==============
async function saveProject() {
  try {
    const method = state.projectId ? 'PUT' : 'POST';
    const url = state.projectId ? `/api/projects/${state.projectId}` : '/api/projects';
    const res = await fetch(url, { method, headers: apiHeaders(), body: JSON.stringify(state) });
    const data = await res.json();
    if (data.id) { state.projectId = data.id; rememberProject(data.id); }
    toast(`Saved. Project ID: ${state.projectId}`);
  } catch (err) { toast('Save failed.'); }
}

function rememberProject(id) {
  const list = JSON.parse(localStorage.getItem('pentscribe_projects') || '[]');
  if (!list.includes(id)) { list.unshift(id); localStorage.setItem('pentscribe_projects', JSON.stringify(list.slice(0, 20))); }
}

async function loadProjectPrompt() {
  const list = JSON.parse(localStorage.getItem('pentscribe_projects') || '[]');
  const id = prompt(`Enter project ID to load${list.length ? `\n\nRecent: ${list.join(', ')}` : ''}`);
  if (!id) return;
  try {
    const res = await fetch(`/api/projects/${id}`);
    if (!res.ok) { toast('Project not found.'); return; }
    state = await res.json();
    state.projectId = id;
    hydrateFormFromState();
    rememberProject(id);
    toast('Project loaded.');
  } catch (err) { toast('Load failed.'); }
}

function hydrateFormFromState() {
  $('#reportTitle').value = state.meta.title || '';
  $('#client').value = state.meta.client || '';
  $('#reportDate').value = state.meta.date || '';
  $('#scope').value = state.meta.scope || '';
  $('#methodology').value = state.meta.methodology || '';
  $('#executiveSummary').value = state.meta.executiveSummary || '';
  renderTemplateGrid();
  renderCvssToggle();
  renderFindings();
}

// ============== Stripe checkout ==============
async function startCheckout() {
  try {
    const res = await fetch('/api/create-checkout-session', { method: 'POST', headers: apiHeaders() });
    const data = await res.json();
    if (data.url) { window.location.href = data.url; }
    else { toast('Stripe not configured yet — add STRIPE_SECRET_KEY on the server.'); }
  } catch (err) { toast('Checkout failed to start.'); }
}

// ============== Usage pill ==============
async function refreshUsage() {
  try {
    const res = await fetch('/api/usage');
    const data = await res.json();
    const left = Math.max(0, data.limit - data.used);
    $('#usagePill').textContent = licenseKey ? '✨ Pro — unlimited' : `${left}/${data.limit} free reports left today`;
  } catch (err) { /* server not reachable in preview */ }
}

// ============== Init ==============
function init() {
  bindStaticEvents();
  state.meta.date = new Date().toISOString().slice(0, 10);
  $('#reportDate').value = state.meta.date;
  $('#methodology').value = state.meta.methodology;
  renderTemplateGrid();
  renderCvssToggle();
  refreshUsage();
  // Seed one example finding so the preview never looks empty on first load
  const f = newFinding();
  f.title = 'Reflected Cross-Site Scripting (XSS) in Search Parameter';
  f.description = 'The "q" parameter on the search endpoint is reflected into the HTML response without output encoding, allowing an attacker to inject arbitrary JavaScript that executes in the victim\'s browser session.';
  f.stepsToReproduce = '1. Navigate to /search?q=<script>alert(1)</script>\n2. Observe the script executes in the page context.';
  f.remediation = '- Apply context-aware output encoding on all reflected parameters.\n- Deploy a Content-Security-Policy header restricting inline script execution.\n- Validate and sanitize input server-side using an allow-list.';
  state.findings.push(f);
  renderFindings();
}

init();
