const test = require('node:test');
const assert = require('node:assert');
const C = require('../page/lib.js');

test('Stufen nach Restlaufzeit', () => {
  assert.strictEqual(C.level(-1), 'expired'); assert.strictEqual(C.level(3), 'err'); assert.strictEqual(C.level(20), 'warn'); assert.strictEqual(C.level(90), 'ok'); assert.strictEqual(C.level(null), 'unknown');
});
test('Alle Zertifikate in einer Liste, kürzeste Restlaufzeit zuerst', () => {
  const l = C.collect({ items: [{ domain: 'a.de', daysLeft: 50, expiresAt: 1 }, { domain: 'b.de', daysLeft: 5, expiresAt: 1, staging: true }], local: { ca: { name: 'CA', daysLeft: 3000 }, leaf: { names: ['localhost'], daysLeft: 300, byCa: true } } });
  assert.deepStrictEqual(l.map((x) => x.key), ['le:b.de', 'le:a.de', 'leaf', 'ca']);
  assert.strictEqual(l[0].kind, 'staging');
});
test('Kurzfassung zählt bald fällige und abgelaufene', () => {
  const s = C.summary(C.collect({ items: [{ domain: 'x', daysLeft: -2 }, { domain: 'y', daysLeft: 6 }, { domain: 'z', daysLeft: 25 }] }));
  assert.deepStrictEqual([s.total, s.expired, s.critical, s.soon, s.next.name], [3, 1, 1, 1, 'x']);
});
test('Leere Antwort stürzt nicht ab', () => { assert.deepStrictEqual(C.collect(null), []); assert.strictEqual(C.summary([]).next, null); });

test('Erinnerungs-Stufen lesbar aufgezählt', () => {
  assert.strictEqual(C.daysList([1, 30, 7], 'de'), '30, 7 und 1');
  assert.strictEqual(C.daysList([14, 3], 'en'), '14 and 3');
  assert.strictEqual(C.daysList([5], 'de'), '5');
});
