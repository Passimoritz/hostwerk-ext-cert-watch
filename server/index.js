'use strict';
/*
 * Certificate watch – server part (native extension, runs as part of Hostwerk).
 *   GET    /api/cert-watch                  → { certs (Hostwerk's own), hosts (watched), missing, limits, remind }
 *   POST   /api/cert-watch/hosts            { target, port?, name? } → add a host and check it right away
 *   DELETE /api/cert-watch/hosts/:id        stop watching
 *   POST   /api/cert-watch/check            check all hosts now        POST /api/cert-watch/hosts/:id/check one host
 * Besides Hostwerk's own certificates (Let's Encrypt, local certificate, local CA) it watches any host and port with a TLS
 * handshake – own mail servers (Stalwart, James) are added by themselves. Checks every few hours (setting), alerts through
 * Hostwerk's notifications when a certificate becomes due or a check fails, and shows up under Live → Watchers.
 * Service "certWatch" for other extensions (status page, uptime wall): list(), summary().
 * Data: data/cert-watch/hosts.json
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const C = require('../lib/certs');
const { probe } = require('./probe');

const MAX_HOSTS = 100;

/** The service itself – deps = { probe } (replaced in the tests). */
function createService(host, deps = {}) {
  const { ctx } = host;
  const doProbe = deps.probe || probe;
  const dir = path.join(ctx.paths.data, 'cert-watch');
  const file = path.join(dir, 'hosts.json');
  const read = () => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return { hosts: [], auto: {} }; } };
  const write = (v) => { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(`${file}.tmp`, JSON.stringify(v, null, 1)); fs.renameSync(`${file}.tmp`, file); };
  const settings = () => {
    let s = {};
    try { s = ctx.extMarket.settingsFor(host.id) || {}; } catch { /* defaults */ }
    return { limits: C.limits(s), notify: s.notify !== false, hours: Math.max(1, Math.min(48, Number(s.interval) || 6)) };
  };

  /** Mail servers of the "Mail server" extension: their TLS ports (implicit TLS and SMTP with STARTTLS) on this PC. */
  const mailTargets = () => {
    const out = [];
    let list = [];
    try { list = ctx.mailserver && ctx.mailserver.list ? ctx.mailserver.list() : []; } catch { list = []; }
    for (const m of list) {
      if (!m || !m.configured || !m.ports) continue;
      const sni = m.hostname || m.domain || undefined;
      for (const [k, label] of [['submissions', 'SMTP'], ['imaps', 'IMAP'], ['submission', 'SMTP STARTTLS']]) {
        const port = Number(m.ports[k]);
        if (!port) continue;
        out.push({ id: `mail-${m.id}-${k}`, auto: true, mail: true, name: `${m.name || m.id} (${label})`, host: '127.0.0.1', servername: sni, port, starttls: k === 'submission' ? 'smtp' : null });
      }
    }
    return out;
  };

  /** Own hosts plus the automatic ones, each with its last result. */
  const hosts = () => {
    const st = read();
    const auto = mailTargets().map((t) => ({ ...t, ...(st.auto && st.auto[t.id] ? { result: st.auto[t.id].result, alerted: st.auto[t.id].alerted } : {}) }));
    return [...st.hosts, ...auto];
  };

  const hostwerkCerts = () => {
    let certs = { items: [], missing: [], local: null };
    try { if (ctx.acme) certs = ctx.acme.certs(); } catch { /* without Let's Encrypt */ }
    const cr = ctx.monitor ? ctx.monitor.certRemind : null;
    // Missing domains with the ids the "Get certificate" button needs
    let domains = [];
    try { domains = ctx.acme ? ctx.acme.list().items : []; } catch { domains = []; }
    const missing = (certs.missing || []).map((m) => { const d = domains.find((x) => x.domain === m.domain) || {}; return { ...m, webId: d.webId || null, vhostId: d.vhostId || null, https: !!d.https }; });
    return { ...certs, missing, remind: cr ? { on: cr.on !== false, days: cr.days } : null };
  };

  /** Notification once per new level (soon → critical → expired, or the check fails). */
  const alertIfNew = (h, rec, lim) => {
    const r = rec.result || {};
    const lv = r.error ? 'failed' : C.level(r.daysLeft, lim);
    const prev = rec.alerted || null;
    rec.alerted = ['warn', 'err', 'expired', 'failed'].includes(lv) ? lv : null;
    if (!rec.alerted || prev === lv || !settings().notify) return;
    const name = h.name || `${h.host}:${h.port}`;
    const title = lv === 'failed' ? host.t('Certificate check failed: {name}', { name }) : lv === 'expired' ? host.t('Certificate expired: {name}', { name }) : host.t('Certificate expires soon: {name}', { name });
    const text = lv === 'failed' ? String(r.error) : host.t('{n} days left – valid until {date}.', { n: r.daysLeft, date: new Date(r.validTo).toISOString().slice(0, 10) });
    try { if (ctx.monitor && ctx.monitor.send) ctx.monitor.send(title, text, { kind: lv === 'warn' ? 'warn' : 'error', event: 'cert', force: true }).catch(() => {}); } catch { /* notifications are optional */ }
  };

  const watcher = () => {
    const lim = settings().limits;
    const list = C.collect(hostwerkCerts(), hosts());
    const bad = list.filter((c) => c.error || ['err', 'expired'].includes(C.level(c.days, lim)));
    try {
      host.watcher({
        id: 'certs', label: host.t('Certificates'), href: '/ext/cert-watch', state: bad.length ? 'alert' : list.length ? 'ok' : 'off',
        detail: bad.length ? bad.map((c) => c.name).slice(0, 5).join(', ') : host.t('All certificates valid for more than {n} days', { n: lim.crit }),
      });
    } catch { /* older Hostwerk without watchers */ }
  };

  const checkOne = async (h) => doProbe({ host: h.host, port: h.port, servername: h.servername, starttls: h.starttls || null });

  let running = null;
  /** Check all hosts (or one) and remember the results. */
  const check = (onlyId = null) => {
    if (running && !onlyId) return running;
    const job = (async () => {
      const lim = settings().limits;
      const list = hosts().filter((h) => !onlyId || h.id === onlyId);
      const results = await Promise.all(list.map(async (h) => [h, await checkOne(h).catch((e) => ({ error: e.message, checkedAt: Date.now() }))]));
      const st = read();
      st.auto = st.auto || {};
      for (const [h, result] of results) {
        const rec = h.auto ? (st.auto[h.id] = st.auto[h.id] || {}) : st.hosts.find((x) => x.id === h.id);
        if (!rec) continue;
        rec.result = result;
        alertIfNew(h, rec, lim);
      }
      // Automatic entries of mail servers that no longer exist are forgotten
      const autoIds = new Set(mailTargets().map((t) => t.id));
      for (const k of Object.keys(st.auto)) if (!autoIds.has(k)) delete st.auto[k];
      write(st);
      watcher();
      host.broadcast({ type: 'cert-watch' });
      return hosts();
    })();
    if (!onlyId) { running = job; job.finally(() => { running = null; }); }
    return job;
  };

  const add = async ({ target, port, name } = {}) => {
    const t = C.parseTarget(target, port);
    if (!t) throw host.error(400, 'Enter a host name or IP address, optionally with a port (e.g. mail.example.org:993).');
    const st = read();
    if (st.hosts.length >= MAX_HOSTS) throw host.error(400, 'At most {n} hosts can be watched.', { n: MAX_HOSTS });
    if (st.hosts.some((h) => h.host === t.host && h.port === t.port)) throw host.error(409, 'This host is already watched.');
    const h = { id: crypto.randomBytes(5).toString('hex'), host: t.host, port: t.port, name: String(name || '').trim().slice(0, 60) || null, starttls: C.startTlsFor(t.port), added: Date.now() };
    st.hosts.push(h);
    write(st);
    await check(h.id);
    return hosts().find((x) => x.id === h.id);
  };

  const remove = (id) => {
    const st = read();
    const n = st.hosts.length;
    st.hosts = st.hosts.filter((h) => h.id !== id);
    if (st.hosts.length === n) throw host.error(404, 'Not found');
    write(st);
    watcher();
  };

  const state = () => ({ certs: hostwerkCerts(), hosts: hosts(), limits: settings().limits, checking: !!running });

  return { state, check, add, remove, hosts, settings, watcher, hostwerkCerts, mailTargets };
}

let timer = null;

function activate(host) {
  const svc = createService(host);
  const r = host.router;
  r.get('/cert-watch', (req, res) => res.json(svc.state()));
  r.post('/cert-watch/hosts', async (req, res) => res.json(await svc.add(req.body || {})));
  r.delete('/cert-watch/hosts/:id', (req, res) => { svc.remove(req.params.id); res.json(svc.state()); });
  r.post('/cert-watch/hosts/:id/check', async (req, res) => { await svc.check(req.params.id); res.json(svc.state()); });
  r.post('/cert-watch/check', async (req, res) => { await svc.check(); res.json(svc.state()); });
  host.provide('certWatch', {
    /** All certificates in one list (Hostwerk's and watched hosts), shortest time left first. */
    list: () => C.collect(svc.hostwerkCerts(), svc.hosts()).map((c) => ({ key: c.key, kind: c.kind, name: c.name, expiresAt: c.expiresAt, days: c.days, error: c.error || null })),
    summary: () => C.summary(C.collect(svc.hostwerkCerts(), svc.hosts()), svc.settings().limits),
  });
  if (!process.env.HW_TEST) {
    // First check shortly after the start, then every few hours (setting, read again each time)
    const loop = (ms) => { timer = setTimeout(async () => { await svc.check().catch(() => {}); loop(svc.settings().hours * 3600000); }, ms); if (timer.unref) timer.unref(); };
    loop(90 * 1000);
  }
  host.on('shutdown', () => clearTimeout(timer));
}

function deactivate() { clearTimeout(timer); timer = null; }

module.exports = { activate, deactivate, createService };
