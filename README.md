# MetaBlock

A project for:

- Browser extensions (Chromium + Firefox) that block Meta-owned domains.
- A local DNS service that blocks Meta domains and DNS answers resolving to Meta ASN prefixes.
- A generator that rebuilds blocklists from seed ASNs/domains/robot signatures.

## GitHub landing (wiki format)

- Wiki home: `wiki/Home.md`
- Wiki sidebar: `wiki/_Sidebar.md`
- Optional visual page: `docs/index.html` (plus `docs/styles.css`, `docs/script.js`)

To use the wiki-formatted landing for GitHub viewers, use `wiki/Home.md` content as your GitHub Wiki `Home` page.

To publish it with GitHub Pages:

1. Open repository **Settings -> Pages**.
2. Under **Build and deployment**, choose **Deploy from a branch**.
3. Select your branch and `/docs` folder.

## What "comprehensive" means here

There is no absolute way to guarantee every possible IP used by a large company forever. This project handles that by:

- Tracking a broad seed ASN set in `blocklists/seed_asns.txt`.
- Pulling currently announced prefixes per ASN from RIPEstat when you run the generator.
- Falling back to `blocklists/snapshot_prefixes.txt` when live ASN APIs are unreachable.
- Blocking seed domains + all subdomains in browser/DNS.
- Shipping robot user-agent signatures (for server-side web bot blocking).

As of **2026-02-18**, the ASN seed file includes Meta ASNs seen in:

- PeeringDB Meta org listing (brands include Facebook, Instagram, WhatsApp, Oculus).
- RADB `AS-FACEBOOK` member set.

Re-run the generator regularly to stay current.

## Project layout

- `scripts/generate_blocklists.py` build all outputs.
- `dns_service/server.py` DNS forwarder + blocker.
- `blocklists/` editable seed data.
- `extensions/chromium/` unpacked Chromium extension.
- `extensions/firefox/` unpacked Firefox extension.
- `generated/` generated outputs (prefixes, rules, DNS configs, metadata).

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/generate_blocklists.py
python dns_service/server.py --port 5353
```

Then point your device/router DNS to this host on port `5353` (or run on port `53` with proper privileges).

## Browser extension install

1. Regenerate rules before install:

```bash
python scripts/generate_blocklists.py
```

2. Chromium:

- Open `chrome://extensions`
- Enable Developer Mode
- Load unpacked -> `extensions/chromium`

3. Firefox:

- Open `about:debugging#/runtime/this-firefox`
- Load Temporary Add-on -> any file inside `extensions/firefox` (for example `manifest.json`)

## DNS behavior

The DNS service blocks in two stages:

1. Query name check: if domain or subdomain matches blocked domains, return `NXDOMAIN`.
2. Response IP check: forward to upstream resolver, then drop answers if any `A`/`AAAA` falls inside blocked prefixes.

Example check:

```bash
dig @127.0.0.1 -p 5353 facebook.com
dig @127.0.0.1 -p 5353 instagram.com
```

## Robot blocking output

The generator writes:

- `generated/meta_robot_user_agents.txt`
- `generated/nginx-meta-robots.conf`

Use this for server-side blocking of known Meta crawlers (`facebookexternalhit`, `Facebot`, `meta-externalagent`, etc.). Browser extensions cannot block inbound crawlers visiting your server.

## Useful commands

```bash
# Rebuild all outputs
python scripts/generate_blocklists.py

# Rebuild from cached prefixes only (no ASN API fetch)
python scripts/generate_blocklists.py --skip-asn-fetch

# Allow generation even if no prefixes are available yet
python scripts/generate_blocklists.py --skip-asn-fetch --allow-empty-prefixes
```
