# Certificate watch

All certificates at a glance: how long they are still valid, which expire soon and which public domains don’t have one yet – with a dashboard tile.

An official [Hostwerk](https://github.com/Passimoritz/hostwerk-public) extension (SDK 2.4) – page in the sidebar and a dashboard tile, in Hostwerk's own design, German and English.

## Permissions

| Permission | Why |
|---|---|
| `read:live` | Certificates and uptime checks (read only) |

Read only – it changes nothing.

## Develop

Logic in `page/lib.js` (no DOM), tests: `node --test tests/*.test.js`. Check: `node check.js . --strict` (Hostwerk SDK).

License: MIT
