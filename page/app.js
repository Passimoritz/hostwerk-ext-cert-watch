// Zertifikats-Wache – Seite und Kachel
const { html, t } = Hostwerk;
const C = Certs;
const BADGE = { ok: 'ok', warn: 'warn', err: 'err', expired: 'err', unknown: '' };
const days = (c) => (c.days == null ? t('unknown') : c.days < 0 ? t('expiredAgo', { n: -c.days }) : t('daysLeft', { n: c.days }));
async function load() {
  let d; try { d = await Hostwerk.get('/live/certs'); } catch (e) { Hostwerk.render('#app', html`<div class="empty"><p>${e.message}</p></div>`); return; }
  const list = C.collect(d); const s = C.summary(list);
  if (Hostwerk.embed === 'widget') {
    Hostwerk.render('#app', html`<div class="stack" style="gap:6px">
      ${s.next ? html`<div><span class="badge ${BADGE[C.level(s.next.days)]}">${days(s.next)}</span> <b>${s.next.name}</b></div>` : html`<div class="muted small">${t('none')}</div>`}
      <div class="small muted">${t('counts', { total: s.total, soon: s.soon + s.critical, expired: s.expired })}</div></div>`);
    return;
  }
  Hostwerk.render('#app', html`
    <div class="grid grid-3" style="margin-bottom:14px">
      <div class="card stat"><div class="k">${t('total')}</div><div class="v">${s.total}</div></div>
      <div class="card stat"><div class="k">${t('soon')}</div><div class="v">${s.soon + s.critical}</div><div class="s">${t('soonHint')}</div></div>
      <div class="card stat"><div class="k">${t('expired')}</div><div class="v">${s.expired}</div></div>
    </div>
    <div class="card">
      ${list.length ? list.map((c) => html`<div class="list-item"><div class="grow" style="min-width:0"><b class="ellipsis">${c.name}</b><div class="small muted">${t('kind.' + c.kind)}${c.sub && c.kind === 'letsencrypt' ? ' · ' + c.sub : ''}${c.expiresAt ? ' · ' + t('until', { date: new Date(c.expiresAt).toLocaleDateString() }) : ''}</div></div><span class="badge ${BADGE[C.level(c.days)]}">${days(c)}</span></div>`) : html`<div class="empty"><p>${t('none')}</p></div>`}
    </div>
    ${(d.missing || []).length ? html`<div class="callout warn" style="margin-top:14px"><div class="callout-body"><b class="callout-title">${t('missingTitle')}</b>${d.missing.map((m) => html`<div class="small">${m.domain} <span class="muted">(${m.web})</span></div>`)}<div class="small muted">${t('missingHint')}</div></div></div>` : ''}`);
}
Hostwerk.ready().then(() => { load(); setInterval(load, 600000); Hostwerk.on('lang', load); });
