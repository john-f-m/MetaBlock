# MetaBlock

MetaBlock is a policy-driven network control project for blocking Meta-owned infrastructure across three enforcement layers:

- browser request blocking (Chromium and Firefox extensions)
- DNS query and response blocking (local DNS forwarder)
- known crawler signature blocking (server-side robot token outputs)

The project is designed to make policy decisions explicit, reproducible, and reviewable. Seed inputs are human-maintained, generated artifacts are deterministic, and each output can be traced to a clear source file.

## Purpose and scope

MetaBlock exists to provide practical defense-in-depth for environments that need to reduce or deny Meta network traffic. It is intentionally transparent: users can inspect the seed data, generation logic, and resulting artifacts without relying on opaque third-party rule sets.

MetaBlock does not claim absolute coverage for all possible Meta infrastructure at all times. Large network operators continuously evolve address space and domain usage. For that reason, MetaBlock combines:

- curated seed ASNs and domains
- live prefix retrieval from ASN APIs
- offline snapshot fallback for continuity during API outages
- repeatable regeneration workflows for ongoing maintenance

## Architecture overview

### Policy inputs

Editable source files in `blocklists/` define the project policy baseline:

- `seed_asns.txt`: ASN scope used to derive currently announced IP prefixes
- `seed_domains.txt`: direct domain and subdomain blocking targets
- `seed_robot_user_agents.txt`: crawler signatures for server-side request blocking
- `snapshot_prefixes.txt`: offline emergency prefix fallback

### Generator

`scripts/generate_blocklists.py` is the single build entry point. It:

- normalizes and validates source data
- fetches announced prefixes per ASN when network access is available
- falls back to cached and snapshot prefix data when needed
- writes synchronized outputs for DNS resolvers, browser extensions, and robot filtering
- records generation metadata in `generated/metadata.json`

### Enforcement outputs

Generated artifacts are written to `generated/` and extension rule directories:

- `generated/meta_domains.txt`
- `generated/meta_prefixes.txt`
- `generated/meta_ipv4_prefixes.txt`
- `generated/meta_ipv6_prefixes.txt`
- `generated/dnsmasq-meta-block.conf`
- `generated/unbound-meta-block.conf`
- `generated/meta_robot_user_agents.txt`
- `generated/nginx-meta-robots.conf`
- `extensions/chromium/rules/rules_1.json`
- `extensions/firefox/rules/rules_1.json`

### DNS service

`dns_service/server.py` implements a local UDP DNS forwarder with two blocking checks:

1. block by query name (domain and subdomain match) with `NXDOMAIN`
2. block by response address when `A` or `AAAA` answers fall inside blocked prefixes

## How to use MetaBlock

### 1. Prerequisites

Recommended baseline:

- Python 3.10 or newer
- `pip` and virtual environment support
- terminal tooling for validation (`dig`, `nslookup`, or equivalent)
- local network privileges if binding to privileged DNS ports (for example port 53)

### 2. Environment setup

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Generate policy outputs

For normal operation (live ASN fetch enabled):

```bash
python scripts/generate_blocklists.py
```

For offline or deterministic rebuild from cached/snapshot data:

```bash
python scripts/generate_blocklists.py --skip-asn-fetch
```

For strict failure behavior when any ASN fetch fails:

```bash
python scripts/generate_blocklists.py --strict
```

### 4. Run the DNS blocker

Basic run:

```bash
python dns_service/server.py --port 5353
```

Example with explicit upstream and debug logging:

```bash
python dns_service/server.py --port 5353 --upstream 1.1.1.1:53 --log-level DEBUG
```

Direct your host, browser test profile, or router to use this resolver endpoint.

### 5. Install browser extensions

Before loading either extension, regenerate rules so the latest policy is present.

```bash
python scripts/generate_blocklists.py
```

Chromium:

1. Open `chrome://extensions`
2. Enable Developer Mode
3. Select `Load unpacked`
4. Choose `extensions/chromium`

Firefox:

1. Open `about:debugging#/runtime/this-firefox`
2. Select `Load Temporary Add-on`
3. Choose a file from `extensions/firefox/` (for example `manifest.json`)

### 6. Apply robot signature outputs (optional server layer)

MetaBlock writes NGINX-ready mapping content in `generated/nginx-meta-robots.conf`.

Typical usage pattern:

- include the map block in `http {}` scope
- evaluate `$block_meta_robot` in server or location context
- return `403` (or site-specific policy) for matched agents

### 7. Validate behavior

Example DNS validation:

```bash
dig @127.0.0.1 -p 5353 facebook.com
dig @127.0.0.1 -p 5353 instagram.com
dig @127.0.0.1 -p 5353 example.org
```

Expected outcomes:

- blocked domains return `NXDOMAIN`
- non-target domains resolve normally
- responses that map into blocked Meta prefixes are filtered

### 8. Operate and maintain

Recommended maintenance cadence:

- regenerate outputs regularly (for example daily or weekly)
- review `generated/metadata.json` for failed ASN fetches
- update seed files when infrastructure changes are observed
- keep snapshot prefixes current as a fallback safety net

## How to contribute

Contributions are welcome for seed data quality, generation logic, DNS behavior, extension rules, and documentation.

### Contribution workflow

1. Open an issue that states the problem, scope, and expected result.
2. Create a focused branch for one logical change set.
3. Make source edits in `blocklists/`, `scripts/`, `dns_service/`, `extensions/`, or `wiki/`.
4. Regenerate artifacts when policy or generation logic changes.
5. Validate behavior locally with reproducible commands.
6. Submit a pull request with clear rationale and evidence.

### Pull request expectations

A strong pull request usually includes:

- concise problem statement
- implementation summary
- risk notes (false positives, false negatives, operational impact)
- validation evidence (commands run and observed outcomes)
- regenerated outputs when source data changed
- documentation updates when behavior changed

### Seed data contribution standards

When editing ASN, domain, or robot seed files:

- provide source attribution in the pull request description
- include collection date and context
- avoid speculative additions without evidence
- prefer minimal, auditable changes over large unverified expansions

### Code and reliability standards

Contributed code should preserve these project properties:

- deterministic outputs from deterministic inputs
- graceful fallback behavior when external APIs fail
- readable logs for operational troubleshooting
- clear separation between source inputs and generated artifacts

### Testing and verification guidance

At minimum, contributors should verify:

- generator runs successfully in both live and offline modes
- DNS service starts and serves expected block behavior
- extension rules are regenerated and load correctly
- documentation remains accurate after functional changes

If you introduce new logic, include automated tests where practical and document manual validation when automation is not yet available.

## Repository map

- `blocklists/`: policy seed inputs maintained by contributors
- `scripts/`: generation logic and build workflow
- `dns_service/`: local DNS forwarder and block policy enforcement
- `extensions/`: Chromium and Firefox extension packages
- `generated/`: machine-generated outputs committed for review/use
- `wiki/`: formal project documentation for GitHub Wiki
- `docs/`: optional GitHub Pages presentation layer

## Support and discussion

For usage questions, contribution proposals, or operational edge cases:

- open a GitHub issue with reproduction details and command output
- include platform details (OS, Python version, resolver setup)
- note whether generation used live ASN fetch or offline mode

Clear issue reports significantly reduce triage time and improve the quality of fixes.
