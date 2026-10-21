![Zertifikats-Wache](banner.svg)

# Zertifikats-Wache

Alle Zertifikate auf einen Blick: Hostwerks eigene und beliebige Hosts – wie lange sie noch gelten, welche bald ablaufen und welche öffentlichen Domains noch keines haben. Mit Kachel für die Übersicht.

[English](README.md) · Offizielle [Hostwerk](https://github.com/Passimoritz/hostwerk-public)-Erweiterung (native Erweiterung, ab Hostwerk 2.11)

## Was sie kann

- **Wo:** Livebetrieb → Betrieb → Zertifikate und Übersichtskachel – seit 2.1.0 ohne eigenen Seitenleisten-Eintrag; die ganze Seite bleibt unter Erweiterungen → Öffnen
- Let’s-Encrypt-Zertifikate, das lokale Server-Zertifikat und die lokale Zertifizierungsstelle
- Beliebige Hosts und Ports per TLS-Handshake: Mailserver (465, 993, 995, SMTP 25/587 mit STARTTLS), Router, NAS, fremde Seiten
- Eigene Mailserver (Erweiterung „Mailserver“) werden von selbst überwacht
- Details je Zertifikat: Aussteller, Namen (SAN), Kette, Schlüsselstärke, ob das System ihm vertraut
- Fehlende Zertifikate für öffentliche Domains per Knopf („Zertifikat holen“)
- Schwellen „bald fällig“ und „kritisch“ unter Einstellungen → Benachrichtigungen & Protokolle; Benachrichtigung über Hostwerks Alarme und ein Wächter unter Livebetrieb → Wächter
- Kachel für die Übersicht mit dem nächsten ablaufenden Zertifikat

An den Hosts ändert sich nichts – nur der TLS-Handshake (bei SMTP dazu EHLO/STARTTLS).

## Für andere Erweiterungen

Dienst `certWatch`: `list()` (alle Zertifikate, kürzeste Restlaufzeit zuerst) und `summary()` – etwa für eine Statusseite oder die Uptime-Wand.

## Daten

`data/cert-watch/hosts.json` – die hinzugefügten Hosts und ihre letzten Ergebnisse.

## Entwickeln

```bash
node --test tests/*.test.js          # Tests (eigenes Test-Zertifikat, verbindet sich nie nach draußen)
node build-native.js .               # Oberfläche bauen (sdk/build-native.js aus hostwerk-public)
node check.js . --strict             # Prüfung wie im Katalog (sdk/check.js)
```

Gemeinsame Logik in `lib/certs.js`, Server-Teil in `server/`, Quelltext der Oberfläche in `ui/src`. Texte im Code sind Englisch, Deutsch steht in `locales/de.json`.

## Lizenz

MIT
