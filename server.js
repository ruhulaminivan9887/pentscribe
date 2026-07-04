require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow,
  TableCell, WidthType, ShadingType
} = require('docx');

const app = express();
app.use(cors());

const PORT = process.env.PORT || 3000;

// -------------------- Supabase (auth verification + database) --------------------
// SUPABASE_URL / SUPABASE_ANON_KEY are safe to expose to the browser by design.
// SUPABASE_SERVICE_ROLE_KEY must NEVER be sent to the browser — server-only, full DB access.
const supabaseAdmin = (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)
  : null;

app.get('/api/config', (req, res) => {
  res.json({
    supabaseUrl: process.env.SUPABASE_URL || null,
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY || null
  });
});

async function requireAuth(req, res, next) {
  if (!supabaseAdmin) return res.status(501).json({ error: 'auth_not_configured' });
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'not_authenticated' });
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data.user) return res.status(401).json({ error: 'invalid_session' });
  req.user = data.user;
  next();
}

async function optionalAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (token && supabaseAdmin) {
    const { data } = await supabaseAdmin.auth.getUser(token);
    if (data?.user) req.user = data.user;
  }
  next();
}

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// -------------------- Admin panel --------------------
// Only this email can access admin endpoints. Set via env var so it's not hardcoded in the repo.
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'ruhulaminivan@gmail.com';

function requireAdmin(req, res, next) {
  if (!req.user || req.user.email !== ADMIN_EMAIL) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

// GET /api/admin/users — every signed-up user, their Pro status, and report count.
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  try {
    const { data: userList, error: userErr } = await supabaseAdmin.auth.admin.listUsers({ perPage: 1000 });
    if (userErr) return res.status(500).json({ error: userErr.message });

    const { data: subs } = await supabaseAdmin.from('subscriptions').select('user_id, status, updated_at');
    const { data: projects } = await supabaseAdmin.from('projects').select('user_id');

    const subMap = new Map((subs || []).map(s => [s.user_id, s]));
    const countMap = new Map();
    (projects || []).forEach(p => countMap.set(p.user_id, (countMap.get(p.user_id) || 0) + 1));

    const rows = userList.users.map(u => ({
      id: u.id,
      email: u.email,
      created_at: u.created_at,
      last_sign_in_at: u.last_sign_in_at,
      email_confirmed: !!u.email_confirmed_at,
      provider: u.app_metadata?.provider || 'email',
      pro: subMap.get(u.id)?.status === 'active',
      pro_since: subMap.get(u.id)?.updated_at || null,
      reports_saved: countMap.get(u.id) || 0
    }));
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/stats — quick top-line numbers for the dashboard.
app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  try {
    const { data: userList } = await supabaseAdmin.auth.admin.listUsers({ perPage: 1000 });
    const { data: subs } = await supabaseAdmin.from('subscriptions').select('status').eq('status', 'active');
    const { data: projects } = await supabaseAdmin.from('projects').select('id', { count: 'exact', head: true });
    res.json({
      totalUsers: userList?.users?.length || 0,
      activeProSubscribers: subs?.length || 0,
      totalReportsSaved: projects?.length || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/grant-pro — manually flip a user to Pro (e.g. comped access, support fix).
app.post('/api/admin/grant-pro', requireAuth, requireAdmin, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  const { userId, status } = req.body; // status: 'active' | 'inactive'
  const { error } = await supabaseAdmin.from('subscriptions').upsert({
    user_id: userId, status: status || 'active', updated_at: new Date().toISOString()
  }, { onConflict: 'user_id' });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// -------------------- Freemium usage limiter --------------------
const usage = new Map();
const FREE_DAILY_LIMIT = 3;

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}

async function isPro(userId, email) {
  if (email === ADMIN_EMAIL) return true; // admin account always has full Pro access
  if (!supabaseAdmin || !userId) return false;
  const { data } = await supabaseAdmin
    .from('subscriptions')
    .select('status')
    .eq('user_id', userId)
    .eq('status', 'active')
    .maybeSingle();
  return !!data;
}

async function checkLimit(req, res, next) {
  if (req.user && await isPro(req.user.id, req.user.email)) return next();
  const key = req.user ? `user:${req.user.id}` : `ip:${getClientIp(req)}`;
  const today = new Date().toISOString().slice(0, 10);
  const entry = usage.get(key);
  if (!entry || entry.date !== today) {
    usage.set(key, { date: today, count: 1 });
    return next();
  }
  if (entry.count >= FREE_DAILY_LIMIT) {
    return res.status(402).json({ error: 'limit_reached', message: 'Free daily limit reached. Upgrade to Pro for unlimited reports.' });
  }
  entry.count += 1;
  next();
}

app.get('/api/usage', optionalAuth, async (req, res) => {
  if (req.user && await isPro(req.user.id, req.user.email)) return res.json({ pro: true });
  const key = req.user ? `user:${req.user.id}` : `ip:${getClientIp(req)}`;
  const today = new Date().toISOString().slice(0, 10);
  const entry = usage.get(key);
  const used = entry && entry.date === today ? entry.count : 0;
  res.json({ used, limit: FREE_DAILY_LIMIT, pro: false });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const pro = await isPro(req.user.id, req.user.email);
  res.json({ id: req.user.id, email: req.user.email, pro, isAdmin: req.user.email === ADMIN_EMAIL });
});

// -------------------- Projects (database-backed, per user) --------------------
app.post('/api/projects', requireAuth, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  const { data, error } = await supabaseAdmin
    .from('projects')
    .insert({ user_id: req.user.id, title: req.body?.meta?.title || 'Untitled report', data: req.body })
    .select('id')
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ id: data.id });
});

app.get('/api/projects', requireAuth, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  const { data, error } = await supabaseAdmin
    .from('projects')
    .select('id, title, updated_at')
    .eq('user_id', req.user.id)
    .order('updated_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  const { data, error } = await supabaseAdmin
    .from('projects')
    .select('data')
    .eq('id', req.params.id)
    .eq('user_id', req.user.id)
    .single();
  if (error || !data) return res.status(404).json({ error: 'not_found' });
  res.json(data.data);
});

app.put('/api/projects/:id', requireAuth, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  const { error } = await supabaseAdmin
    .from('projects')
    .update({ title: req.body?.meta?.title || 'Untitled report', data: req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.delete('/api/projects/:id', requireAuth, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  const { error } = await supabaseAdmin.from('projects').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// -------------------- AI Assist (Anthropic API) --------------------
app.post('/api/ai-assist', optionalAuth, checkLimit, async (req, res) => {
  try {
    const { mode, context } = req.body;
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
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 500, messages: [{ role: 'user', content: prompt }] })
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
app.post('/api/export/docx', optionalAuth, checkLimit, (req, res) => {
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

    children.push(new Paragraph({ text: 'Findings Summary', heading: HeadingLevel.HEADING_1 }));
    const headerRow = new TableRow({
      children: ['#', 'Title', 'Severity', 'CVSS', 'Status'].map(t => new TableCell({
        children: [new Paragraph({ text: t })], shading: { fill: '1A1A24', type: ShadingType.CLEAR }
      }))
    });
    const rows = (findings || []).map((f, i) => new TableRow({
      children: [String(i + 1), f.title || '-', f.severity || '-', String(f.cvssScore || '-'), f.status || 'Open']
        .map(t => new TableCell({ children: [new Paragraph({ text: t })] }))
    }));
    children.push(new Table({ rows: [headerRow, ...rows], width: { size: 100, type: WidthType.PERCENTAGE } }));

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
app.post('/api/export/markdown', optionalAuth, checkLimit, (req, res) => {
  const { meta, findings } = req.body;
  let md = `# ${meta.title || 'Penetration Test Report'}\n\n`;
  md += `**Assessment Type:** ${meta.template}  \n**Client:** ${meta.client || '-'}  \n**Date:** ${meta.date || '-'}  \n**CVSS Version:** ${meta.cvssVersion}\n\n`;
  md += `## Executive Summary\n\n${meta.executiveSummary || '-'}\n\n## Scope\n\n${meta.scope || '-'}\n\n## Methodology\n\n${meta.methodology || '-'}\n\n`;
  md += `## Findings Summary\n\n| # | Title | Severity | CVSS | Status |\n|---|---|---|---|---|\n`;
  (findings || []).forEach((f, i) => { md += `| ${i + 1} | ${f.title} | ${f.severity} | ${f.cvssScore || '-'} | ${f.status || 'Open'} |\n`; });
  md += `\n`;
  (findings || []).forEach((f, i) => {
    md += `## ${i + 1}. ${f.title}\n\n**Severity:** ${f.severity}  **CVSS ${meta.cvssVersion}:** ${f.cvssScore} (${f.cvssVector || 'N/A'})\n\n`;
    md += `### Description\n${f.description || '-'}\n\n### Steps to Reproduce\n${f.stepsToReproduce || '-'}\n\n### Evidence\n${f.evidence || '-'}\n\n### Remediation\n${f.remediation || '-'}\n\n`;
  });
  res.setHeader('Content-Disposition', `attachment; filename="${(meta.title || 'report').replace(/\s+/g, '_')}.md"`);
  res.setHeader('Content-Type', 'text/markdown');
  res.send(md);
});

// -------------------- Stripe --------------------
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  if (!stripe) return res.status(501).json({ error: 'stripe_not_configured' });
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      client_reference_id: req.user.id,
      customer_email: req.user.email,
      success_url: `${req.headers.origin}/?upgraded=true`,
      cancel_url: `${req.headers.origin}/?upgraded=false`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(501).end();
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (!supabaseAdmin) return res.json({ received: true });

  // A checkout just succeeded — turn Pro ON.
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.client_reference_id;
    if (userId) {
      await supabaseAdmin.from('subscriptions').upsert({
        user_id: userId,
        status: 'active',
        stripe_customer_id: session.customer,
        updated_at: new Date().toISOString()
      }, { onConflict: 'user_id' });
    }
  }

  // Subscription was cancelled outright — turn Pro OFF.
  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    await supabaseAdmin.from('subscriptions')
      .update({ status: 'inactive', updated_at: new Date().toISOString() })
      .eq('stripe_customer_id', sub.customer);
  }

  // Renewal failed (card declined, etc.) or subscription status otherwise changed —
  // sync our record to match Stripe's actual current status.
  if (event.type === 'customer.subscription.updated') {
    const sub = event.data.object;
    const isActive = sub.status === 'active' || sub.status === 'trialing';
    await supabaseAdmin.from('subscriptions')
      .update({ status: isActive ? 'active' : 'inactive', updated_at: new Date().toISOString() })
      .eq('stripe_customer_id', sub.customer);
  }

  res.json({ received: true });
});

app.listen(PORT, () => console.log(`PentScribe server running on port ${PORT}`));
