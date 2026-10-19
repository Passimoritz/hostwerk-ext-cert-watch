// Zertifikats-Wache – Logik ohne Seite (auch in Node testbar)
(function (root) {
  /** Zustand nach Restlaufzeit: abgelaufen, kritisch (≤ 7 Tage), bald (≤ 30 Tage), gut. */
  function level(days) { if (days == null) return 'unknown'; if (days < 0) return 'expired'; if (days <= 7) return 'err'; if (days <= 30) return 'warn'; return 'ok'; }
  /** Alles in eine Liste: Let's Encrypt, lokales Server-Zertifikat, lokale CA – kürzeste Restlaufzeit zuerst. */
  function collect(d) {
    const out = [];
    for (const c of (d && d.items) || []) out.push({ key: 'le:' + c.domain, kind: c.staging ? 'staging' : 'letsencrypt', name: c.domain, sub: c.web || '', expiresAt: c.expiresAt, days: c.daysLeft });
    const l = d && d.local;
    if (l && l.leaf) out.push({ key: 'leaf', kind: 'local', name: (l.leaf.names || []).slice(0, 3).join(', ') || 'localhost', sub: l.leaf.byCa ? 'ca' : 'self', expiresAt: l.leaf.expiresAt, days: l.leaf.daysLeft });
    if (l && l.ca) out.push({ key: 'ca', kind: 'ca', name: l.ca.name || 'Hostwerk Local CA', sub: '', expiresAt: l.ca.expiresAt, days: l.ca.daysLeft });
    return out.sort((a, b) => (a.days == null ? 1e9 : a.days) - (b.days == null ? 1e9 : b.days));
  }
  /** Kurzfassung für die Kachel. */
  function summary(list) {
    const n = (lv) => list.filter((c) => level(c.days) === lv).length;
    return { total: list.length, expired: n('expired'), critical: n('err'), soon: n('warn'), next: list.find((c) => c.days != null) || null };
  }
  /** [30, 14, 7] → „30, 14 und 7“ (de) bzw. „30, 14 and 7“ (en) */
  function daysList(days, lang) { const l = [...(days || [])].map(Number).filter((x) => x > 0).sort((a, b) => b - a); if (l.length < 2) return l.join(''); return `${l.slice(0, -1).join(', ')} ${lang === 'en' ? 'and' : 'und'} ${l[l.length - 1]}`; }
  const api = { daysList, level, collect, summary };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.Certs = api;
})(typeof window !== 'undefined' ? window : globalThis);
