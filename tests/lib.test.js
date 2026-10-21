'use strict';
const test = require('node:test');
const assert = require('node:assert');
const C = require('../lib/certs.js');

test('levels by days left, with own thresholds', () => {
  assert.strictEqual(C.level(-1), 'expired'); assert.strictEqual(C.level(3), 'err'); assert.strictEqual(C.level(20), 'warn'); assert.strictEqual(C.level(90), 'ok'); assert.strictEqual(C.level(null), 'unknown');
  const lim = C.limits({ warnDays: 60, critDays: 14 });
  assert.deepStrictEqual(lim, { warn: 60, crit: 14 });
  assert.strictEqual(C.level(45, lim), 'warn');
  assert.strictEqual(C.level(10, lim), 'err');
  assert.deepStrictEqual(C.limits({}), { warn: 30, crit: 7 }, 'defaults');
  assert.deepStrictEqual(C.limits({ warnDays: 5, critDays: 9 }), { warn: 5, crit: 4 }, 'critical stays below "soon"');
  assert.deepStrictEqual(C.limits({ warnDays: 10, critDays: 0 }), { warn: 10, crit: 0 });
});

test('all certificates in one list, shortest time left first – including watched hosts', () => {
  const l = C.collect({ items: [{ domain: 'a.de', daysLeft: 50, expiresAt: 1 }, { domain: 'b.de', daysLeft: 5, expiresAt: 1, staging: true }], local: { ca: { name: 'CA', daysLeft: 3000 }, leaf: { names: ['localhost'], daysLeft: 300, byCa: true } } },
    [{ id: 'h1', host: 'mail.x.de', port: 993, result: { daysLeft: 2, validTo: 5 } }, { id: 'h2', host: 'router', port: 443, result: { error: 'Connection refused' } }, { id: 'm', mail: true, auto: true, name: 'Mail (IMAP)', host: '127.0.0.1', port: 993 }]);
  assert.deepStrictEqual(l.map((x) => x.key), ['host:h1', 'le:b.de', 'le:a.de', 'leaf', 'ca', 'host:h2', 'host:m']);
  assert.strictEqual(l[1].kind, 'staging');
  assert.strictEqual(l[0].name, 'mail.x.de:993');
  assert.strictEqual(l.find((x) => x.key === 'host:h2').error, 'Connection refused');
  assert.strictEqual(l.find((x) => x.key === 'host:m').kind, 'mail');
});

test('summary counts due, expired and failed checks', () => {
  const s = C.summary(C.collect({ items: [{ domain: 'x', daysLeft: -2 }, { domain: 'y', daysLeft: 6 }, { domain: 'z', daysLeft: 25 }] }, [{ id: 'f', host: 'h', port: 1, result: { error: 'x' } }]));
  assert.deepStrictEqual([s.total, s.expired, s.critical, s.soon, s.failed, s.next.name], [4, 1, 1, 1, 1, 'x']);
});

test('empty answer does not crash', () => { assert.deepStrictEqual(C.collect(null), []); assert.strictEqual(C.summary([]).next, null); });

test('reminder steps listed readably', () => {
  assert.strictEqual(C.daysList([1, 30, 7], 'de'), '30, 7 und 1');
  assert.strictEqual(C.daysList([14, 3], 'en'), '14 and 3');
  assert.strictEqual(C.daysList([5], 'de'), '5');
});

test('host input: host, host:port, URL, IPv6', () => {
  assert.deepStrictEqual(C.parseTarget('mail.example.org:993'), { host: 'mail.example.org', port: 993 });
  assert.deepStrictEqual(C.parseTarget('https://Example.org/path'), { host: 'example.org', port: 443 });
  assert.deepStrictEqual(C.parseTarget('192.168.178.1', 8443), { host: '192.168.178.1', port: 8443 });
  assert.deepStrictEqual(C.parseTarget('[fd00::1]:443'), { host: 'fd00::1', port: 443 });
  assert.strictEqual(C.parseTarget('bad host'), null);
  assert.strictEqual(C.parseTarget('x.de:70000'), null);
  assert.strictEqual(C.startTlsFor(587), 'smtp');
  assert.strictEqual(C.startTlsFor(993), null);
});

test('key strength', () => {
  assert.strictEqual(C.keyText({ keyType: 'EC', bits: 256, curve: 'prime256v1' }), 'EC 256 (prime256v1)');
  assert.ok(C.weakKey({ keyType: 'RSA', bits: 1024 }));
  assert.ok(!C.weakKey({ keyType: 'RSA', bits: 2048 }));
});
