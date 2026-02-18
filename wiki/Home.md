# MetaBlock

AI-assisted network controls for blocking Meta-owned infrastructure across browser, DNS, and crawler layers.

## At a glance

- Blocks Meta domains in Chromium and Firefox extensions.
- Runs a local DNS service that blocks:
  - domain queries (`NXDOMAIN`)
  - resolved IPs inside blocked Meta prefixes
- Generates bot signature output for server-side crawler blocking.

## Why this exists

Single-layer blocking is easy to bypass. MetaBlock keeps one policy source and applies it across multiple enforcement points so coverage is inspectable and repeatable.

## Core components

### 1. Generator

`scripts/generate_blocklists.py`

- Builds all generated artifacts from seed files.
- Pulls announced prefixes per ASN when network access is available.
- Falls back to `blocklists/snapshot_prefixes.txt` if live ASN fetch fails.

### 2. DNS service

`dns_service/server.py`

- Forwards to an upstream resolver.
- Returns `NXDOMAIN` for blocked domains/subdomains.
- Drops responses when `A`/`AAAA` answers match blocked Meta prefixes.

### 3. Browser extensions

- Chromium: `extensions/chromium/`
- Firefox: `extensions/firefox/`

Both load generated `declarativeNetRequest` rules from `rules/rules_1.json`.

### 4. Robot signatures

- `generated/meta_robot_user_agents.txt`
- `generated/nginx-meta-robots.conf`

Use for server-side blocking of known Meta crawler user-agents.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/generate_blocklists.py --skip-asn-fetch
python dns_service/server.py --port 5353
```

## ASN coverage notes

Seed ASNs are defined in `blocklists/seed_asns.txt` and currently include:

- `AS32934`
- `AS63293`
- `AS54115`
- `AS34825`
- `AS11917`

These are maintained for Meta ecosystem coverage including Facebook, Instagram, WhatsApp, and Oculus-related infrastructure.

## Useful commands

```bash
# Full generation (live fetch when available)
python scripts/generate_blocklists.py

# Offline-safe generation
python scripts/generate_blocklists.py --skip-asn-fetch

# Run DNS blocker
python dns_service/server.py --port 5353
```

## Project layout

- `blocklists/` seed input files
- `generated/` machine-generated outputs
- `scripts/` generation logic
- `dns_service/` local DNS blocker
- `extensions/` browser extension manifests + rules
- `wiki/` GitHub wiki-format pages
