![Certificate watch](banner.svg)

# Certificate watch

All certificates at a glance: Hostwerk’s own and any host – how long they are still valid, which expire soon and which public domains don’t have one yet. With a dashboard tile.

[Deutsch](README.de.md) · An official [Hostwerk](https://github.com/Passimoritz/hostwerk-public) extension (native extension, Hostwerk 2.11 or newer)

## What it does

- Let’s Encrypt certificates, the local server certificate and the local certificate authority
- Any host and port with a TLS handshake: mail servers (465, 993, 995, SMTP 25/587 with STARTTLS), router, NAS, other sites
- Your own mail servers (extension “Mail server”) are watched by themselves
- Details per certificate: issuer, names (SAN), chain, key strength, whether the system trusts it
- Missing certificates for public domains with one button (“Get certificate”)
- Thresholds “due soon” and “critical” in Settings → Notifications & logs; notifications through Hostwerk’s alerts and a watcher under Live → Watchers
- Dashboard tile with the next certificate to expire

Nothing is changed on the hosts – only the TLS handshake (and EHLO/STARTTLS for SMTP).

## For other extensions

Service `certWatch`: `list()` (all certificates, shortest time left first) and `summary()` – for example for a status page or the uptime wall.

## Data

`data/cert-watch/hosts.json` – the hosts you added and their last results.

## Develop

```bash
node --test tests/*.test.js          # tests (own test certificate, never connects outside this PC)
node build-native.js .               # build the interface (sdk/build-native.js from hostwerk-public)
node check.js . --strict             # same check as the catalogue (sdk/check.js)
```

Shared logic in `lib/certs.js`, server part in `server/`, interface source in `ui/src`. Texts in the code are English, German is in `locales/de.json`.

## License

MIT
