'use strict';
/*
 * TLS handshake with any host and port – web pages, mail servers (also SMTP with STARTTLS), router, NAS …
 * Reads the certificate the other side presents: valid until, issuer, names (SAN), chain, key strength and whether the
 * system trusts it. Nothing is sent besides the handshake (and EHLO/STARTTLS for SMTP).
 */
const net = require('net');
const tls = require('tls');

const DAY = 86400000;

/** Connection/TLS error → short English text (German in locales/de.json) instead of raw OpenSSL output. */
function errText(e) {
  const c = e && e.code;
  const m = String((e && e.message) || e || '');
  if (c === 'ECONNREFUSED') return 'Connection refused';
  if (c === 'ENOTFOUND' || c === 'EAI_AGAIN' || c === 'EAI_NONAME') return 'Host not found';
  if (c === 'ECONNRESET' || c === 'EPIPE' || /socket disconnected|socket hang up/i.test(m)) return 'The other side closed the connection';
  if (c === 'EHOSTUNREACH' || c === 'ENETUNREACH' || c === 'EADDRNOTAVAIL') return 'Host not reachable';
  if (c === 'ETIMEDOUT') return 'No answer (timeout)';
  if (c === 'ERR_SSL_WRONG_VERSION_NUMBER' || /wrong version number|packet length too long|unknown protocol/i.test(m)) return 'No TLS on this port';
  if (/^ERR_SSL_|alert|handshake/i.test(String(c || '')) || /SSL routines/i.test(m)) return 'TLS handshake failed';
  return m;
}

/** Name from a certificate subject/issuer object: CN, else O. */
const nameOf = (x) => (x && (x.CN || x.O || x.OU)) || '';

/** Certificate (from getPeerCertificate(true)) → plain facts. */
function describe(cert, socket, now = Date.now(), name = null) {
  // The chain alone is not enough (rejectUnauthorized is off to read every certificate): the names have to fit, too
  let trusted = socket ? !!socket.authorized : null;
  let trustError = socket && !socket.authorized ? String(socket.authorizationError || '') : null;
  if (trusted && name) { let bad = null; try { bad = tls.checkServerIdentity(name, cert); } catch (e) { bad = e; } if (bad) { trusted = false; trustError = bad.code || 'ERR_TLS_CERT_ALTNAME_INVALID'; } }
  const validTo = cert.valid_to ? Date.parse(cert.valid_to) : null;
  const validFrom = cert.valid_from ? Date.parse(cert.valid_from) : null;
  const san = String(cert.subjectaltname || '').split(/,\s*/).map((x) => x.replace(/^(DNS|IP Address):/, '')).filter(Boolean);
  const chain = [];
  const seen = new Set();
  for (let c = cert; c && !seen.has(c.fingerprint256); c = c.issuerCertificate) {
    seen.add(c.fingerprint256);
    chain.push({ subject: nameOf(c.subject), issuer: nameOf(c.issuer), validTo: c.valid_to ? Date.parse(c.valid_to) : null });
    if (c.issuerCertificate === c) break;
  }
  // Node: RSA keys come with modulus/exponent, EC keys with the curve name
  const keyType = cert.modulus ? 'RSA' : cert.asn1Curve || cert.nistCurve ? 'EC' : null;
  return {
    subject: nameOf(cert.subject), issuer: nameOf(cert.issuer), issuerOrg: (cert.issuer && cert.issuer.O) || '',
    san: san.slice(0, 50), sanCount: san.length, validFrom, validTo, daysLeft: validTo ? Math.floor((validTo - now) / DAY) : null,
    keyType, bits: cert.bits || null, curve: cert.asn1Curve || cert.nistCurve || null,
    serial: cert.serialNumber || '', fingerprint: cert.fingerprint256 || '', chain: chain.slice(0, 6),
    trusted, trustError,
    protocol: socket && socket.getProtocol ? socket.getProtocol() : null, checkedAt: now,
  };
}

/** SMTP: read the greeting, EHLO, STARTTLS – then the TLS handshake on the same connection. */
function smtpStartTls(sock, timeout) {
  return new Promise((resolve, reject) => {
    let buf = '';
    let step = 0;
    const done = (e) => { sock.removeListener('data', onData); clearTimeout(timer); if (e) reject(e); else resolve(); };
    const timer = setTimeout(() => done(new Error('No answer from the mail server')), timeout);
    const onData = (chunk) => {
      buf += chunk.toString('latin1');
      // A complete reply ends with a line "NNN text" (no dash after the code)
      const lines = buf.split(/\r?\n/);
      const last = lines.filter(Boolean).pop() || '';
      if (!/^\d{3} /.test(last)) return;
      const code = Number(last.slice(0, 3));
      buf = '';
      if (step === 0) { if (code !== 220) return done(new Error(`Mail server says ${code}`)); step = 1; sock.write('EHLO hostwerk.local\r\n'); }
      else if (step === 1) { if (code !== 250) return done(new Error(`Mail server says ${code}`)); step = 2; sock.write('STARTTLS\r\n'); }
      else if (step === 2) { if (code !== 220) return done(new Error('The mail server does not offer STARTTLS')); done(); }
    };
    sock.on('data', onData);
  });
}

/**
 * probe({ host, port, servername, starttls: 'smtp' | null, timeout }) → describe(…) or { error }
 * connect(opts) can be replaced in tests.
 */
function probe({ host, port, servername, starttls = null, timeout = 8000 }, deps = {}) {
  const connectTcp = deps.connectTcp || ((o) => net.connect(o));
  const connectTls = deps.connectTls || ((o, cb) => tls.connect(o, cb));
  const sni = servername || (net.isIP(host) ? undefined : host);
  return new Promise((resolve) => {
    let finished = false;
    const finish = (r, s) => { if (finished) return; finished = true; try { if (s) s.destroy(); } catch { /* ignore */ } resolve(r); };
    const timer = setTimeout(() => finish({ error: 'No answer (timeout)', checkedAt: Date.now() }), timeout + 1000);
    const handshake = (socket) => {
      const opts = { host, port, servername: sni, rejectUnauthorized: false, timeout, ...(socket ? { socket } : {}) };
      const t = connectTls(opts, () => {
        clearTimeout(timer);
        const cert = t.getPeerCertificate(true);
        if (!cert || !Object.keys(cert).length) return finish({ error: 'The other side sent no certificate', checkedAt: Date.now() }, t);
        finish(describe(cert, t, Date.now(), sni || host), t);
      });
      t.on('error', (e) => { clearTimeout(timer); finish({ error: errText(e), checkedAt: Date.now() }, t); });
      t.on('timeout', () => { clearTimeout(timer); finish({ error: 'No answer (timeout)', checkedAt: Date.now() }, t); });
    };
    if (!starttls) { handshake(null); return; }
    const s = connectTcp({ host, port });
    s.setTimeout(timeout, () => finish({ error: 'No answer (timeout)', checkedAt: Date.now() }, s));
    s.on('error', (e) => { clearTimeout(timer); finish({ error: errText(e), checkedAt: Date.now() }, s); });
    s.once('connect', () => smtpStartTls(s, timeout).then(() => { s.setTimeout(0); handshake(s); }, (e) => { clearTimeout(timer); finish({ error: e.message, checkedAt: Date.now() }, s); }));
  });
}

module.exports = { probe, describe, smtpStartTls, errText };
