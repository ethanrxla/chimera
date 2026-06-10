# Shopify HackerOne Bug Bounty Workspace

Source context: HackerOne program text pasted on 2026-06-10.

## Program Snapshot

- Program: Shopify
- Program URL: `https://hackerone.com/shopify`
- Main site: `https://www.shopify.com`
- Max bounty: `$200,000` for Critical vulnerabilities.
- Current campaign: Authentication & ATO.
- Campaign window: Monday June 8 through Friday June 26, 2026.
- Campaign asset: `Authentication & ATO`.
- Multiplier: Medium `1.25x`, High `1.5x`, Critical `2x`.
- Reports must show concrete security impact with a working proof of concept.

## Critical Rules

- Test only stores and accounts you created with your HackerOne `YOURHANDLE@wearehackerone.com` email.
- Do not test live merchant stores or interact with data that is not yours.
- Do not contact Shopify Support for testing, pre-validation, bounty questions, or status updates.
- Do not use credential stuffing, brute force without a rate-limit bypass, social engineering, or public disclosure before resolution.
- Report as soon as a vulnerability is validated.
- For leaked credentials, authenticate only enough to confirm validity, then immediately deauthenticate without exercising functionality.

## Campaign-Covered Surfaces

- Merchant admin.
- Partners dashboard.
- `accounts.shopify.com`.
- Shop App authentication and Login with Shop.
- Checkout authentication.
- Session token issuance for Admin, Storefront, and app contexts.
- B2B buyer authentication, including merchant-configured SSO and SAML.
- Two-factor authentication recovery flows.

## Campaign-In-Scope Bug Classes

- Authentication bypass.
- MFA bypass or downgrade.
- OAuth, SSO, SAML, or SCIM flaws with concrete authentication or ATO impact.
- Session management issues on authentication surfaces.
- Account takeover through authentication flows.
- Authorization flaws in authentication/account APIs, including MFA settings, OAuth grants, recovery email, and sessions.

## Not Multiplier-Eligible

These may still receive standard payout if otherwise valid:

- Pre-account squatting.
- Customer storefront accounts.
- POS staff authentication.
- Account enumeration.
- Brute force that does not bypass an existing rate limit.
- Self-XSS on login surfaces.
- OAuth issues without authentication impact, such as standalone open redirect, missing state, or redirect URI misconfiguration.
- Generic bugs outside auth chained into account impact, such as unrelated storefront XSS leading to session theft.

## Local Files

- [scope.md](/home/ethanrisden/whitehat/chimera/bounties/shopify/scope.md): scope, accounts, payout notes.
- [attack-vectors.md](/home/ethanrisden/whitehat/chimera/bounties/shopify/attack-vectors.md): prioritized test ideas.
- [chimera-runbook.md](/home/ethanrisden/whitehat/chimera/bounties/shopify/chimera-runbook.md): safe local execution workflow.
- [scope.yaml](/home/ethanrisden/whitehat/chimera/bounties/shopify/scope.yaml): Chimera-compatible scope manifest.
- [report-template.md](/home/ethanrisden/whitehat/chimera/bounties/shopify/report-template.md): HackerOne submission skeleton.

