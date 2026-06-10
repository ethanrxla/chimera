# Shopify Chimera Runbook

## Setup

1. Create all test accounts with the HackerOne `YOURHANDLE@wearehackerone.com` alias.
2. Create two development stores and, if needed, two partner organizations.
3. Replace placeholders in [scope.yaml](/home/ethanrisden/whitehat/chimera/bounties/shopify/scope.yaml).
4. Capture fresh cookies/tokens in Burp or the browser for Account A and Account B.
5. Store secrets outside git-tracked files, for example in a local `.env` or password manager.

## Safe Defaults

```yaml
requests_per_second: 2
concurrency: 2
max_requests_per_scan: 1000
allow_destructive: false
```

Use `GET`, `HEAD`, and `OPTIONS` for recon. Use state-changing methods only for a single, explicit proof against disposable data in your own store/account.

## Recommended Local Flow

```bash
cd /home/ethanrisden/whitehat/chimera
./chimera/scripts/run_core.sh
```

In another terminal:

```bash
cd /home/ethanrisden/whitehat/chimera/chimera/chimera-cli
cargo run -- console
```

Operator console prompts:

```text
set program Shopify
set workflow standard
set pipeline recon
set target https://accounts.shopify.com
scan quick
oracle Can Account A modify Account B MFA, recovery, OAuth grant, or session objects by swapping object IDs?
```

## Manual Evidence Capture

For auth/ATO findings, preserve:

- Full request and response for the legitimate Account B action that creates the target object.
- Full request and response for the attempted Account A replay.
- Before/after screenshots for Account B state.
- Object IDs and account/store IDs, with unrelated tokens redacted.
- Timestamp and exact accounts/stores used.
- Confirmation that only researcher-owned stores/accounts were touched.

## Endpoint Discovery Targets

Start with browser-driven flows rather than broad crawling:

- Login and logout.
- MFA enrollment, challenge, remember-device, recovery, and disablement.
- Password reset and recovery email changes.
- OAuth app install and reauthorization.
- Partner organization invites and role changes.
- Store switching in admin.
- Checkout authentication and Login with Shop.

## Validation Rules

Only promote a finding to report-ready when:

- Account A can affect or access Account B authentication/account state, or
- Account A can authenticate into the wrong shop/org/user context, or
- a token/session issued for one context is accepted in another security boundary.

Do not promote:

- Account enumeration alone.
- Missing OAuth `state` without demonstrated auth impact.
- Open redirect without token/account/session impact.
- Scanner-only observations.
- Self-XSS on login surfaces.

## Artifact Layout

```text
bounties/shopify/
  artifacts/          Raw local evidence exports and run IDs.
  findings/           Report-ready drafts.
  notes/              Scratch notes, flow maps, endpoint inventories.
```

