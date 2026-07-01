require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow,
  TableCell, WidthType, BorderStyle, AlignmentType, ShadingType
} = require('docx');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// -------------------- Simple freemium usage limiter (per IP, per day) --------------------
const usage = new Map(); // ip -> { date, count }
const FREE_DAILY_LIMIT = 3;
const proUsers = new Set(); // license keys / emails unlocked via Stripe (in-memory demo store)

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}

function checkLimit(req, res, next) {
  const license = req.headers['x-license-key'];
  if (license && proUsers.has(license)) return next(); // pro user, unlimited

  const ip = getClientIp(req);
  const today = new Date().toISOString().slice(0, 10);
  const entry = usage.get(ip);
  if (!entry || entry.date !== today) {
    usage.set(ip, { date: today, count: 1 });
    return next();
  }
  if (entry.count >= FREE_DAILY_LIMIT) {
    return res.status(402).json({ error: 'limit_reached', message: 'Free daily limit reached. Upgrade to Pro for unlimited reports.' });
  }
  entry.count += 1;
  next();
}

app.get('/api/usage', (req, res) => {
  const ip = getClientIp(req);
  const today = new Date().toISOString().slice(0, 10);
  const entry = usage.get(ip);
  const used = entry && entry.date === today ? entry.count : 0;
  res.json({ used, limit: FREE_DAILY_LIMIT });
});

// -------------------- Project save/load (JSON, per project id) --------------------
app.post('/api/projects', (req, res) => {
  const id = uuidv4();
  fs.writeFileSync(path.join(DATA_DIR, `${id}.json`), JSON.stringify(req.body, null, 2));
  res.json({ id });
});

app.get('/api/projects/:id', (req, res) => {
  const file = path.join(DATA_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'not_found' });
  res.json(JSON.parse(fs.readFileSync(file, 'utf-8')));
});

app.put('/api/projects/:id', (req, res) => {
  const file = path.join(DATA_DIR, `${req.params.id}.json`);
  fs.writeFileSync(file, JSON.stringify(req.body, null, 2));
  res.json({ ok: true });
});

// -------------------- AI Assist (Anthropic API) --------------------
// Requires ANTHROPIC_API_KEY set as an environment variable on the server (Render/host dashboard).
app.post('/api/ai-assist', checkLimit, async (req, res) => {
  try {
    const { mode, context } = req.body; // mode: 'description' | 'remediation' | 'executive_summary'
    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(501).json({ error: 'ai_not_configured', message: 'Set ANTHROPIC_API_KEY on the server to enable AI assist.' });
    }
    const prompts = {
      description: `Write a concise, technically precise vulnerability description (3-5 sentences) for a pentest report finding titled "${context.title}" in the "${context.template}" assessment category. Severity: ${context.severity}. Notes from tester: ${context.notes || 'none'}. Do not include a title or heading, just the description paragraph.`,
      remediation: `Write concise, actionable remediation steps (bulleted, 3-5 items) for a pentest finding titled "${context.title}" with severity ${context.severity}. Notes: ${context.notes || 'none'}. Return plain text bullets starting with "- ".`,
      executive_summary: `Write a 2-paragraph executive summary for a penetration test report. Assessment type: ${context.template}. Scope: ${context.scope || 'not specified'}. Total findings: ${context.findingsCount}, breakdown: ${JSON.stringify(context.severityBreakdown)}. Write for a non-technical executive audience, professional tone, no headers.`
    };
    const prompt = prompts[mode];
    if (!prompt) return res.status(400).json({ error: 'invalid_mode' });

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 500,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const data = await response.json();
    const text = (data.content || []).map(b => b.text || '').join('\n').trim();
    res.json({ text });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error', message: err.message });
  }
});

// -------------------- Word (.docx) export --------------------
const SEV_COLORS = { Critical: 'C0152F', High: 'E63946', Medium: 'FFB703', Low: 'FFD166', Informational: '8888AA' };

app.post('/api/export/docx', (req, res) => {
  try {
    const { meta, findings } = req.body;
    const children = [];

    children.push(new Paragraph({ text: meta.title || 'Penetration Test Report', heading: HeadingLevel.TITLE }));
    children.push(new Paragraph({ text: `${meta.template} Assessment`, heading: HeadingLevel.HEADING_3 }));
    children.push(new Paragraph({ text: `Client: ${meta.client || '-'}    Date: ${meta.date || '-'}    CVSS: ${meta.cvssVersion || '3.1'}`, spacing: { after: 300 } }));

    children.push(new Paragraph({ text: 'Executive Summary', heading: HeadingLevel.HEADING_1 }));
    children.push(new Paragraph({ text: meta.executiveSummary || 'No summary provided.', spacing: { after: 300 } }));

    children.push(new Paragraph({ text: 'Scope', heading: HeadingLevel.HEADING_1 }));
    children.push(new Paragraph({ text: meta.scope || 'No scope provided.', spacing: { after: 300 } }));

    children.push(new Paragraph({ text: 'Methodology', heading: HeadingLevel.HEADING_1 }));
    children.push(new Paragraph({ text: meta.methodology || 'Standard methodology applied per assessment type.', spacing: { after: 300 } }));

    // Remediation summary table
    children.push(new Paragraph({ text: 'Findings Summary', heading: HeadingLevel.HEADING_1 }));
    const headerRow = new TableRow({
      children: ['#', 'Title', 'Severity', 'CVSS', 'Status'].map(t => new TableCell({
        children: [new Paragraph({ text: t, style: 'strong' })],
        shading: { fill: '1A1A24', type: ShadingType.CLEAR }
      }))
    });
    const rows = (findings || []).map((f, i) => new TableRow({
      children: [
        new Paragraph({ text: String(i + 1) }),
        new Paragraph({ text: f.title || '-' }),
        new Paragraph({ text: f.severity || '-' }),
        new Paragraph({ text: String(f.cvssScore || '-') }),
        new Paragraph({ text: f.status || 'Open' })
      ].map(p => new TableCell({ children: [p] }))
    }));
    children.push(new Table({ rows: [headerRow, ...rows], width: { size: 100, type: WidthType.PERCENTAGE } }));

    // Detailed findings
    (findings || []).forEach((f, i) => {
      children.push(new Paragraph({ text: `${i + 1}. ${f.title}`, heading: HeadingLevel.HEADING_1, spacing: { before: 400 } }));
      children.push(new Paragraph({ children: [new TextRun({ text: `Severity: ${f.severity}  |  CVSS ${meta.cvssVersion}: ${f.cvssScore} (${f.cvssVector || 'N/A'})`, bold: true })] }));
      children.push(new Paragraph({ text: 'Description', heading: HeadingLevel.HEADING_3 }));
      children.push(new Paragraph({ text: f.description || '-' }));
      children.push(new Paragraph({ text: 'Steps to Reproduce', heading: HeadingLevel.HEADING_3 }));
      children.push(new Paragraph({ text: f.stepsToReproduce || '-' }));
      children.push(new Paragraph({ text: 'Evidence', heading: HeadingLevel.HEADING_3 }));
      children.push(new Paragraph({ text: f.evidence || '-' }));
      children.push(new Paragraph({ text: 'Remediation', heading: HeadingLevel.HEADING_3 }));
      children.push(new Paragraph({ text: f.remediation || '-' }));
    });

    const doc = new Document({ sections: [{ children }] });
    Packer.toBuffer(doc).then(buffer => {
      res.setHeader('Content-Disposition', `attachment; filename="${(meta.title || 'report').replace(/\s+/g, '_')}.docx"`);
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      res.send(buffer);
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'export_failed', message: err.message });
  }
});

// -------------------- Markdown export --------------------
app.post('/api/export/markdown', (req, res) => {
  const { meta, findings } = req.body;
  let md = `# ${meta.title || 'Penetration Test Report'}\n\n`;
  md += `**Assessment Type:** ${meta.template}  \n**Client:** ${meta.client || '-'}  \n**Date:** ${meta.date || '-'}  \n**CVSS Version:** ${meta.cvssVersion}\n\n`;
  md += `## Executive Summary\n\n${meta.executiveSummary || '-'}\n\n`;
  md += `## Scope\n\n${meta.scope || '-'}\n\n`;
  md += `## Methodology\n\n${meta.methodology || '-'}\n\n`;
  md += `## Findings Summary\n\n| # | Title | Severity | CVSS | Status |\n|---|---|---|---|---|\n`;
  (findings || []).forEach((f, i) => {
    md += `| ${i + 1} | ${f.title} | ${f.severity} | ${f.cvssScore || '-'} | ${f.status || 'Open'} |\n`;
  });
  md += `\n`;
  (findings || []).forEach((f, i) => {
    md += `## ${i + 1}. ${f.title}\n\n`;
    md += `**Severity:** ${f.severity}  **CVSS ${meta.cvssVersion}:** ${f.cvssScore} (${f.cvssVector || 'N/A'})\n\n`;
    md += `### Description\n${f.description || '-'}\n\n`;
    md += `### Steps to Reproduce\n${f.stepsToReproduce || '-'}\n\n`;
    md += `### Evidence\n${f.evidence || '-'}\n\n`;
    md += `### Remediation\n${f.remediation || '-'}\n\n`;
  });
  res.setHeader('Content-Disposition', `attachment; filename="${(meta.title || 'report').replace(/\s+/g, '_')}.md"`);
  res.setHeader('Content-Type', 'text/markdown');
  res.send(md);
});

// -------------------- Stripe --------------------
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
}

app.post('/api/create-checkout-session', async (req, res) => {
  if (!stripe) return res.status(501).json({ error: 'stripe_not_configured' });
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${req.headers.origin}/?upgraded=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin}/?upgraded=false`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Stripe webhook - marks a license key as pro when payment succeeds.
// NOTE: needs raw body, mounted before express.json for this path in production if you enable it.
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(501).end();
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    proUsers.add(session.customer_email || session.id);
  }
  res.json({ received: true });
});

app.listen(PORT, () => console.log(`PentScribe server running on port ${PORT}`));
