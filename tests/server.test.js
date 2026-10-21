'use strict';
/*
 * Server part: real TLS handshake (own test certificate), SMTP with STARTTLS, watched hosts, automatic mail server
 * entries, notifications once per level, watcher. Never connects to anything outside this PC.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const net = require('net');
const tls = require('tls');
const path = require('path');
process.env.HW_TEST = '1';
const { probe } = require('../server/probe');
const { createService } = require('../server/index');

const key = fs.readFileSync(path.join(__dirname, 'fixtures', 'test.key'));
const cert = fs.readFileSync(path.join(__dirname, 'fixtures', 'test.crt'));
const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));

test('TLS handshake reads validity, issuer, names, key and trust', async () => {
  const srv = tls.createServer({ key, cert }, (s) => s.end());
  const port = await listen(srv);
  const r = await probe({ host: '127.0.0.1', port, servername: 'cert-watch.test', timeout: 3000 });
  srv.close();
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.subject, 'cert-watch.test');
  assert.strictEqual(r.issuerOrg, 'Hostwerk Test');
  assert.deepStrictEqual(r.san, ['cert-watch.test', 'localhost']);
  assert.strictEqual(r.keyType, 'RSA');
  assert.strictEqual(r.bits, 2048);
  assert.ok(r.daysLeft > 300);
  assert.strictEqual(r.trusted, false, 'self-signed → not trusted');
  assert.ok(r.trustError);
  assert.ok(r.chain.length >= 1);
});

test('SMTP with STARTTLS', async () => {
  const ctx = tls.createSecureContext({ key, cert });
  const srv = net.createServer((s) => {
    s.write('220 test ESMTP\r\n');
    s.on('data', (d) => {
      const line = d.toString();
      if (/^EHLO/i.test(line)) s.write('250-test\r\n250 STARTTLS\r\n');
      else if (/^STARTTLS/i.test(line)) { s.write('220 go ahead\r\n'); s.removeAllListeners('data'); const t = new tls.TLSSocket(s, { isServer: true, secureContext: ctx }); t.on('error', () => {}); }
    });
    s.on('error', () => {});
  });
  const port = await listen(srv);
  const r = await probe({ host: '127.0.0.1', port, servername: 'cert-watch.test', starttls: 'smtp', timeout: 3000 });
  srv.close();
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.subject, 'cert-watch.test');
});

test('refused connection is a readable error', async () => {
  const srv = net.createServer();
  const port = await listen(srv);
  srv.close();
  await new Promise((r) => setTimeout(r, 50));
  const r = await probe({ host: '127.0.0.1', port, timeout: 2000 });
  assert.strictEqual(r.error, 'Connection refused');
});

function setup({ mail = [] } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hw-certwatch-'));
  const sent = []; const watchers = []; const events = [];
  let days = 40;
  let settings = { warnDays: 30, critDays: 7 };
  const host = {
    id: 'cert-watch',
    ctx: {
      paths: { data: dir },
      extMarket: { settingsFor: () => settings },
      mailserver: { list: () => mail },
      acme: { certs: () => ({ items: [{ domain: 'a.de', daysLeft: 80, expiresAt: 1 }], missing: [{ domain: 'b.de', web: 'Apache' }], local: null }), list: () => ({ items: [{ domain: 'b.de', webId: 'apache', vhostId: 'v1', https: true }] }) },
      monitor: { certRemind: { on: true, days: [30, 7] }, send: async (title, text, o) => { sent.push({ title, text, o }); } },
    },
    t: (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? v[k] : m)) : s),
    error: (st, m) => Object.assign(new Error(m), { status: st }),
    watcher: (w) => watchers.push(w),
    broadcast: (m) => events.push(m),
  };
  const calls = [];
  const fakeProbe = async (o) => { calls.push(o); if (o.host === 'down.example') return { error: 'Connection refused', checkedAt: Date.now() }; return { subject: o.host, daysLeft: days, validTo: Date.now() + days * 86400000, checkedAt: Date.now() }; };
  const svc = createService(host, { probe: fakeProbe });
  return { svc, sent, watchers, events, calls, setDays: (d) => { days = d; }, setSettings: (s) => { settings = s; } };
}

test('watched hosts: add, check, notify once per level, remove', async () => {
  const { svc, sent, watchers, events, setDays } = setup();
  const h = await svc.add({ target: 'mail.example.org:993', name: 'Mail' });
  assert.strictEqual(h.result.daysLeft, 40);
  assert.strictEqual(sent.length, 0, 'not due yet');
  await assert.rejects(svc.add({ target: 'mail.example.org:993' }), /already watched/);
  await assert.rejects(svc.add({ target: 'not a host' }), /host name or IP/);

  setDays(20); await svc.check();
  assert.strictEqual(sent.length, 1);
  assert.match(sent[0].title, /expires soon: Mail/);
  await svc.check();
  assert.strictEqual(sent.length, 1, 'same level → no second message');
  setDays(3); await svc.check();
  assert.strictEqual(sent.length, 2, 'critical → new message');
  assert.strictEqual(watchers[watchers.length - 1].state, 'alert');
  assert.ok(events.some((e) => e.type === 'cert-watch'));

  await svc.add({ target: 'down.example' });
  assert.ok(sent.some((s) => /check failed: down\.example:443/.test(s.title)));

  const st = svc.state();
  assert.deepStrictEqual(st.limits, { warn: 30, crit: 7 });
  assert.strictEqual(st.certs.missing[0].vhostId, 'v1', 'missing domain carries the ids for "Get certificate"');
  svc.remove(h.id);
  assert.ok(!svc.hosts().some((x) => x.id === h.id));
});

test('own mail servers are watched by themselves (implicit TLS and STARTTLS)', async () => {
  const { svc, calls } = setup({ mail: [{ id: 'mailserver', name: 'Stalwart', configured: true, hostname: 'mail.example.org', ports: { submissions: 465, imaps: 993, submission: 587, http: 8095 } }, { id: 'x', configured: false, ports: { imaps: 1 } }] });
  const list = svc.hosts();
  assert.deepStrictEqual(list.map((h) => [h.port, h.starttls, h.servername]), [[465, null, 'mail.example.org'], [993, null, 'mail.example.org'], [587, 'smtp', 'mail.example.org']]);
  await svc.check();
  assert.strictEqual(calls.length, 3);
  assert.ok(svc.hosts().every((h) => h.result && h.result.daysLeft === 40), 'results of automatic entries are kept');
});

test('notifications can be switched off', async () => {
  const { svc, sent, setDays, setSettings } = setup();
  setSettings({ notify: false });
  setDays(1);
  await svc.add({ target: 'x.example' });
  assert.strictEqual(sent.length, 0);
});
