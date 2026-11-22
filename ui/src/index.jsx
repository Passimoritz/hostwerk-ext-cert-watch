import { useEffect, useState } from 'react';
import { Shield, ShieldCheck, Plus, RotateCw, Trash2, ChevronDown, ChevronRight, CloudOff, Mail, Globe, Lock, KeyRound, BellRing, Settings2, RefreshCw } from 'lucide-react';
import { post, del, useApi, on, waitJob } from '@hostwerk/api';
import { Btn, Empty, Loading, TileEmpty, InfoTip, Callout, toast, confirmDialog } from '@hostwerk/ui';
import { t, pl } from '@hostwerk/i18n';
import C from '../../lib/certs.js';
import './style.css';

/*
 * Certificate watch: Hostwerk's own certificates (Let's Encrypt, local certificate, local CA) plus any host and port
 * (mail server, router, other sites) – time left, details (issuer, names, chain, key), missing certificates with one
 * button, thresholds from the settings. Dates follow Hostwerk's language (document language), not the system.
 */
const locale = () => (typeof document !== 'undefined' && document.documentElement.lang) || 'en';
const day = (ts) => (ts ? new Date(ts).toLocaleDateString(locale(), { day: '2-digit', month: '2-digit', year: 'numeric' }) : '–');
const when = (ts) => (ts ? new Date(ts).toLocaleString(locale(), { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '–');
const BADGE = { ok: 'ok', warn: 'warn', err: 'err', expired: 'err', unknown: '' };
const KIND = { letsencrypt: 'Let’s Encrypt', staging: 'Let’s Encrypt (staging)', local: 'Local server certificate', ca: 'Local certificate authority', host: 'Watched host', mail: 'Mail server' };
// Less than a day left: "expires today" (or "within 24 hours" when that is already tomorrow) instead of "0 days left"
const today = (ts) => !!ts && new Date(ts).toDateString() === new Date().toDateString();
const daysText = (c) => (c.error ? t('Check failed') : c.days == null ? t('unknown') : c.days < 0 ? pl(-c.days, 'expired {n} day ago', 'expired {n} days ago') : c.days === 0 ? (!c.expiresAt || today(c.expiresAt) ? t('expires today') : t('expires within 24 hours')) : pl(c.days, '{n} day left', '{n} days left'));
// Thresholds live in Hostwerk's settings (settingsTab "notifications" = Settings → Notifications)
const openSettings = () => { location.hash = '/settings/meldungen'; };

/** Reload when the server reports new results (after a check). */
function useLive(reload) {
  useEffect(() => on('cert-watch', () => reload({ silent: true })), [reload]);
}

function Details({ c }) {
  const r = c.details;
  if (!r) return null;
  return (
    <div className="cw-details small">
      <div><span className="muted">Issued by</span> {r.issuer || '–'}{r.issuerOrg && r.issuerOrg !== r.issuer ? ` (${r.issuerOrg})` : ''}</div>
      <div><span className="muted">Valid</span> {day(r.validFrom)} – {day(r.validTo)}</div>
      {r.san && r.san.length > 0 && <div className="cw-wrap"><span className="muted">Names</span> {r.san.join(', ')}{r.sanCount > r.san.length ? ` ${t('+{n} more', { n: r.sanCount - r.san.length })}` : ''}</div>}
      <div><span className="muted">Key</span> {C.keyText(r) || '–'}{C.weakKey(r) ? <span className="badge warn cw-gap">weak</span> : null}{r.protocol ? ` · ${r.protocol}` : ''}</div>
      <div><span className="muted">Trusted</span> {r.trusted ? <span className="badge ok">yes</span> : <span className="badge warn">{t('no – {why}', { why: t(C.trustText(r.trustError)) })}</span>}</div>
      {r.chain && r.chain.length > 0 && (
        <div><span className="muted">Chain</span>
          <ol className="cw-chain">{r.chain.map((x, i) => <li key={i}>{x.subject || '?'} <span className="muted">{t('by {issuer}, until {date}', { issuer: x.issuer || '?', date: day(x.validTo) })}</span></li>)}</ol>
        </div>
      )}
      <div className="tiny muted">{t('Checked {when}', { when: when(r.checkedAt) })}</div>
    </div>
  );
}

function Row({ c, lim, reload }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(null);
  const lv = c.error ? 'err' : C.level(c.days, lim);
  const h = c.host;
  const Icon = c.kind === 'mail' ? Mail : c.kind === 'host' ? Globe : Lock;
  const check = async () => { setBusy('check'); try { await post(`/cert-watch/hosts/${encodeURIComponent(h.id)}/check`); reload({ silent: true }); } catch (e) { toast.error(e); } setBusy(null); };
  const remove = async () => {
    if (!(await confirmDialog({ title: 'Stop watching?', text: t('{name} is no longer checked.', { name: c.name }), confirm: 'Stop watching', danger: true }))) return;
    setBusy('del'); try { await del(`/cert-watch/hosts/${encodeURIComponent(h.id)}`); reload({ silent: true }); } catch (e) { toast.error(e); } setBusy(null);
  };
  return (
    <div className="list-item cw-row">
      <div className="cw-main">
        {c.details ? (
          <button type="button" className="btn ghost xs icon" aria-expanded={open} aria-label={open ? 'Hide details' : 'Show details'} title={open ? 'Hide details' : 'Show details'} onClick={() => setOpen(!open)}>{open ? <ChevronDown /> : <ChevronRight />}</button>
        ) : <Icon size={16} className="muted cw-ico" aria-hidden="true" />}
        <div className="grow cw-min">
          <b className="ellipsis">{c.name}</b>
          <div className="small muted ellipsis">{t(KIND[c.kind] || c.kind)}{c.sub && c.kind === 'letsencrypt' ? ` · ${c.sub}` : ''}{(c.kind === 'host' || c.kind === 'mail') && c.sub !== c.name ? ` · ${c.sub}` : ''}{c.expiresAt ? ` · ${t('valid until {date}', { date: day(c.expiresAt) })}` : ''}{c.error ? ` · ${t(c.error)}` : ''}</div>
        </div>
        <span className={`badge ${c.error ? 'err' : BADGE[lv]}`}>{daysText(c)}</span>
        {h && <button type="button" className="btn ghost xs icon" aria-label="Check now" title="Check now" disabled={!!busy} onClick={check}><RefreshCw className={busy === 'check' ? 'spin' : ''} /></button>}
        {h && !h.auto && <button type="button" className="btn ghost xs icon" aria-label="Stop watching" title="Stop watching" disabled={!!busy} onClick={remove}><Trash2 /></button>}
      </div>
      {open && <Details c={c} />}
    </div>
  );
}

function AddHost({ reload }) {
  const [target, setTarget] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const ok = !!C.parseTarget(target);
  const add = async (e) => {
    e.preventDefault();
    if (!ok) return;
    setBusy(true);
    try { const h = await post('/cert-watch/hosts', { target, name }); setTarget(''); setName(''); reload({ silent: true }); if (h && h.result && h.result.error) toast.error(t('{name}: {error}', { name: h.name || C.addr(h.host, h.port), error: t(h.result.error) })); else toast.success('Host added'); } catch (err) { toast.error(err); }
    setBusy(false);
  };
  return (
    <form className="cw-add" onSubmit={add}>
      <input className="input sm grow" aria-label="Host and port" placeholder="e.g. mail.example.org:993 or 192.168.178.1" value={target} onChange={(e) => setTarget(e.target.value)} />
      <input className="input sm cw-name" aria-label="Name (optional)" placeholder="Name (optional)" maxLength={60} value={name} onChange={(e) => setName(e.target.value)} />
      <Btn className="sm" type="submit" icon={Plus} busy={busy} disabled={!ok}>Watch</Btn>
      <InfoTip title="Any host and port">Hostwerk opens a TLS connection and reads the certificate – web pages (443), mail (465, 993, 995 and 25/587 with STARTTLS), router or NAS. Nothing else is sent.</InfoTip>
    </form>
  );
}

function Missing({ list, reload }) {
  const [busy, setBusy] = useState(null);
  const get = async (m) => {
    const agree = await confirmDialog({ title: t('Get a certificate for {domain}?', { domain: m.domain }), text: 'Hostwerk asks Let’s Encrypt for a free certificate. The domain has to point to this PC and port 80 has to be reachable from outside.', confirm: 'Get certificate', checkbox: { label: 'I agree to the Let’s Encrypt terms of service', checked: false } });
    if (!agree || agree.ok === false) return;
    if (agree.checked === false) { toast.error('Without agreeing to the terms Let’s Encrypt issues no certificate.'); return; }
    setBusy(m.domain);
    try { const r = await post('/live/domains/cert', { webId: m.webId, vhostId: m.vhostId, agree: true }); await waitJob(r.job); toast.success(t('Certificate for {domain} is ready', { domain: m.domain })); reload({ silent: true }); } catch (e) { toast.error(e); }
    setBusy(null);
  };
  return (
    <Callout kind="warn" dismissible={false} title="Public domains without a certificate">
      {list.map((m) => (
        <div key={m.domain} className="row-tight cw-missing">
          <span className="grow small">{m.domain} <span className="muted">({m.web})</span></span>
          {m.webId && m.vhostId ? <Btn className="xs" icon={Lock} busy={busy === m.domain} onClick={() => get(m)}>Get certificate</Btn> : <a className="btn xs ghost" href="#/live/online">Domains</a>}
        </div>
      ))}
    </Callout>
  );
}

/** embedded: as a section (Go live → Protection) – Hostwerk's card says "Certificates" already, the list needs no second title. */
function CertPage({ embedded = false }) {
  const st = useApi('/cert-watch', [], { poll: false });
  const [busy, setBusy] = useState(false);
  useLive(st.reload);
  if (!st.data && st.error) return <div className="page"><Empty icon={CloudOff} title="Could not load the certificates" text={st.error} action={<Btn icon={RotateCw} onClick={() => st.reload()}>Try again</Btn>} /></div>;
  if (!st.data) return <div className="page"><Loading /></div>;
  const d = st.data;
  const lim = d.limits || C.DEFAULT_LIMITS;
  const list = C.collect(d.certs, d.hosts);
  const s = C.summary(list, lim);
  const checkAll = async () => { setBusy(true); try { st.setData(await post('/cert-watch/check')); toast.success('All hosts checked'); } catch (e) { toast.error(e); } setBusy(false); };
  return (
    <div className="page fade-in">
      <div className="page-head">
        <div>
          <h1><Shield /> Certificate watch</h1>
          <p>How long every certificate is still valid – Hostwerk’s own and any host you add.</p>
        </div>
        <div className="actions">
          <Btn className="ghost" icon={RefreshCw} busy={busy} onClick={checkAll}>Check all</Btn>
          <Btn className="ghost" icon={Settings2} onClick={openSettings}>Thresholds</Btn>
        </div>
      </div>
      {st.error && <Callout kind="warn" dismissible={false}>{t('Could not refresh: {error}', { error: st.error })}</Callout>}
      <div className="grid grid-4 cw-stats">
        <div className="card stat"><div className="k">Certificates</div><div className="v">{s.total}</div></div>
        <div className="card stat"><div className="k">Expiring soon</div><div className="v">{s.soon + s.critical}</div><div className="s">{t('within the next {n} days', { n: lim.warn })}</div></div>
        <div className="card stat"><div className="k">Expired</div><div className="v">{s.expired}</div></div>
        <div className="card stat"><div className="k">Checks failed</div><div className="v">{s.failed}</div></div>
      </div>
      {(d.certs.missing || []).length > 0 && <Missing list={d.certs.missing} reload={st.reload} />}
      <div className="card">
        {!embedded && <div className="card-head"><KeyRound size={16} /><h3>All certificates</h3></div>}
        <div className="card-body">
          <AddHost reload={st.reload} />
        </div>
        {list.length ? list.map((c) => <Row key={c.key} c={c} lim={lim} reload={st.reload} />) : <div className="card-body"><Empty icon={ShieldCheck} title="No certificates yet" text="Add a host above or get a certificate for a public domain under Go live → Online → Addresses." /></div>}
      </div>
      {d.certs.remind && (
        <Callout kind={d.certs.remind.on ? 'info' : 'warn'} dismissible={false} title={d.certs.remind.on ? 'Hostwerk reminds you' : 'Reminders are off'}>
          <div className="small">{d.certs.remind.on ? t('{days} days before expiry you get one message each – on your phone and the alerts you set up.', { days: C.daysList(d.certs.remind.days, locale().slice(0, 2)) }) : 'Switch them on under Go live → Monitoring → Watchers so no certificate expires unnoticed.'}</div>
          <div className="row-tight cw-remind"><a className="btn sm ghost" href="#/live/ueberwachung/waechter"><BellRing size={14} />Set up reminders</a></div>
        </Callout>
      )}
    </div>
  );
}

/** Dashboard tile: the next certificate to expire and the counts. */
function CertTile() {
  const st = useApi('/cert-watch', [], { poll: false });
  useLive(st.reload);
  if (!st.data && st.error) return <TileEmpty icon={CloudOff} text={t('Could not load: {error}', { error: st.error })} action={t('Try again')} onClick={() => st.reload()} />;
  if (!st.data) return <div className="card-body"><div className="hw-skeleton cw-skel" /></div>;
  const lim = st.data.limits || C.DEFAULT_LIMITS;
  const list = C.collect(st.data.certs, st.data.hosts);
  const s = C.summary(list, lim);
  if (!list.length) return <TileEmpty icon={ShieldCheck} text="No certificates yet" href="#/ext/cert-watch" />;
  return (
    <a className="card-body stack cw-tile" href="#/ext/cert-watch">
      {s.next && <div className="row-tight"><span className={`badge ${BADGE[C.level(s.next.days, lim)]}`}>{daysText(s.next)}</span><b className="ellipsis">{s.next.name}</b></div>}
      <div className="small muted">{pl(s.total, '{n} certificate', '{n} certificates')} · {t('{soon} due soon · {expired} expired', { soon: s.soon + s.critical, expired: s.expired })}{s.failed ? ` · ${pl(s.failed, '{n} check failed', '{n} checks failed')}` : ''}</div>
    </a>
  );
}

/** Die ganze Seite als Abschnitt: wie bei den Reitern ohne eigenen Titelblock (.ext-embedded), die Knöpfe bleiben. */
function CertSection() {
  return <div className="ext-embedded"><CertPage embedded /></div>;
}

export default {
  pages: { main: CertPage },
  sections: {
    // 2.3 (Hostwerk mit SDK 3.11+): Abschnitt in Livebetrieb → Schutz (#/live/schutz/certs) – abgelaufene Zertifikate sind
    // ein Schutz-Thema der Adressen nach draußen; System ist seit SDK 3.12 Lage, Dienste, Leistung, Protokolle, Wartung, Änderungen
    'live.schutz': [{ id: 'certs', title: 'Certificates', icon: ShieldCheck, Component: CertSection, order: 40 }],
  },
  slots: {
    // Ältere Hostwerk (vor SDK 3.11): Reiter System → Zertifikate (seit 2.2.0, vorher Livebetrieb → Betrieb), ganze Seite,
    // Hostwerk blendet ihren Titel aus. fallback: true – Hostwerk mit Abschnitten lässt ihn weg (Abschnitt live.schutz oben).
    'system.tabs': [{ id: 'certs', title: 'Certificates', icon: ShieldCheck, Component: CertPage, order: 40, fallback: true }],
    'dashboard.tiles': [{ id: 'certs', title: 'Certificate watch', icon: ShieldCheck, size: 'third', Component: CertTile }],
  },
};
