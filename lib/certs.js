'use strict';
/*
 * Certificate watch – logic without server or page (shared by both, testable in Node).
 * Thresholds come from the extension settings (days until "soon" and "critical") instead of fixed 30/7.
 */
const DEFAULT_LIMITS = { warn: 30, crit: 7 };

/** Clean limits: whole days, critical below "soon". */
function limits(s) {
  const warn = Math.max(1, Math.min(365, Math.round(Number(s && s.warnDays) || DEFAULT_LIMITS.warn)));
  const c = s ? s.critDays : undefined;
  const critRaw = c === undefined || c === null || c === '' || !Number.isFinite(Number(c)) ? DEFAULT_LIMITS.crit : Number(c);
  const crit = Math.max(0, Math.min(warn - 1, Math.round(critRaw)));
  return { warn, crit };
}

/** State by days left: expired, critical (≤ crit), soon (≤ warn), good. */
function level(days, lim = DEFAULT_LIMITS) {
  if (days == null) return 'unknown';
  if (days < 0) return 'expired';
  if (days <= lim.crit) return 'err';
  if (days <= lim.warn) return 'warn';
  return 'ok';
}

/**
 * Everything in one list: Let's Encrypt, local server certificate, local CA and the hosts the user watches
 * (web pages, mail servers, router …) – shortest time left first.
 */
function collect(d, watched) {
  const out = [];
  for (const c of (d && d.items) || []) out.push({ key: `le:${c.domain}`, kind: c.staging ? 'staging' : 'letsencrypt', name: c.domain, sub: c.web || '', expiresAt: c.expiresAt, days: c.daysLeft });
  const l = d && d.local;
  if (l && l.leaf) out.push({ key: 'leaf', kind: 'local', name: (l.leaf.names || []).slice(0, 3).join(', ') || 'localhost', sub: l.leaf.byCa ? 'ca' : 'self', expiresAt: l.leaf.expiresAt, days: l.leaf.daysLeft });
  if (l && l.ca) out.push({ key: 'ca', kind: 'ca', name: l.ca.name || 'Hostwerk Local CA', sub: '', expiresAt: l.ca.expiresAt, days: l.ca.daysLeft });
  for (const h of watched || []) {
    const r = h.result || {};
    out.push({ key: `host:${h.id}`, kind: h.mail ? 'mail' : 'host', name: h.name || `${h.host}:${h.port}`, sub: `${h.host}:${h.port}`, expiresAt: r.validTo || null, days: r.daysLeft ?? null, error: r.error || null, details: r.error ? null : r, host: h });
  }
  return out.sort((a, b) => (a.days == null ? 1e9 : a.days) - (b.days == null ? 1e9 : b.days));
}

/** Short summary for the tile. */
function summary(list, lim = DEFAULT_LIMITS) {
  const n = (lv) => list.filter((c) => level(c.days, lim) === lv).length;
  return { total: list.length, expired: n('expired'), critical: n('err'), soon: n('warn'), failed: list.filter((c) => c.error).length, next: list.find((c) => c.days != null) || null };
}

/** [30, 14, 7] → "30, 14 und 7" (de) or "30, 14 and 7" (en) */
function daysList(days, lang) {
  const l = [...(days || [])].map(Number).filter((x) => x > 0).sort((a, b) => b - a);
  if (l.length < 2) return l.join('');
  return `${l.slice(0, -1).join(', ')} ${lang === 'en' ? 'and' : 'und'} ${l[l.length - 1]}`;
}

/** "RSA 2048", "EC 256 (prime256v1)" */
function keyText(r) {
  if (!r || !r.keyType) return '';
  return `${r.keyType}${r.bits ? ` ${r.bits}` : ''}${r.curve ? ` (${r.curve})` : ''}`;
}

/** Weak key? RSA under 2048 bits, EC under 256 bits. */
function weakKey(r) { return !!(r && r.bits && ((r.keyType === 'RSA' && r.bits < 2048) || (r.keyType === 'EC' && r.bits < 256))); }

/** Host entry from the form: "mail.example.org:993" or host + port. */
function parseTarget(input, port) {
  let host = String(input || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '');
  let p = Number(port) || null;
  const m = host.match(/^\[([0-9a-f:]+)\](?::(\d+))?$/i) || host.match(/^([^:]+):(\d+)$/);
  if (m) { host = m[1]; if (m[2]) p = Number(m[2]); }
  if (!/^[a-z0-9.-]{1,253}$/i.test(host) && !/^[0-9a-f:]{2,39}$/i.test(host)) return null;
  if (!p) p = 443;
  if (!Number.isInteger(p) || p < 1 || p > 65535) return null;
  return { host: host.toLowerCase(), port: p };
}

/** Which protocol to speak before TLS: SMTP on 25/587 (and their alternatives) uses STARTTLS. */
function startTlsFor(port) { return [25, 587, 2525, 5587].includes(Number(port)) ? 'smtp' : null; }

module.exports = { DEFAULT_LIMITS, limits, level, collect, summary, daysList, keyText, weakKey, parseTarget, startTlsFor };
