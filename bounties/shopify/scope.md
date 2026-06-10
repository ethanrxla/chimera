# Shopify Scope Notes

## Research Accounts

Use only accounts and stores you own.

```text
Researcher email: YOURHANDLE@wearehackerone.com
Store A: REPLACE_WITH_ATTACKER_STORE.myshopify.com
Store B: REPLACE_WITH_VICTIM_STORE.myshopify.com
Partner org A: REPLACE_WITH_PARTNER_ORG_A
Partner org B: REPLACE_WITH_PARTNER_ORG_B
Shop account A: REPLACE_WITH_SHOP_ACCOUNT_A
Shop account B: REPLACE_WITH_SHOP_ACCOUNT_B
```

## High-Priority In-Scope Assets

- `https://accounts.shopify.com`
- `https://admin.shopify.com`
- `https://partners.shopify.com`
- `https://shop.app`
- `https://checkout.shopify.com`
- Owned `*.myshopify.com` development stores.
- Authentication/session endpoints observed during login, MFA, OAuth, app install, checkout login, and recovery flows.

## Explicit Safety Boundaries

- Do not probe stores you did not create.
- Do not enumerate real merchants, customers, staff, or partner accounts.
- Keep request rates low and targeted.
- Avoid scanner-wide crawling unless the allowlist is limited to your owned assets and global auth surfaces.
- Do not use destructive mutations except against disposable data in your own test stores.
- Do not attempt to bypass sanctions, payment, tax, or payout systems.

## Bounty Notes

- Core findings are calculated using Shopify's Bug Bounty Calculator.
- Valid non-core vulnerabilities are calculated with confidentiality, integrity, and availability requirements set to Low.
- Scores under 3 may result in a `$500` bounty.
- Current average bounty details in pasted program text:
  - Low: average `$556`.
  - Medium: average `$3,841`.
  - High: average `$3,270`.
  - Critical: average `$132,300`.

## Report Eligibility Checklist

- Root cause is under Shopify control.
- Target is an in-scope asset or accepted asset.
- The proof of concept demonstrates concrete Shopify, merchant, partner, or Shop-user impact.
- Evidence is from researcher-owned accounts/stores only.
- If requesting campaign multiplier, the report is filed against `Authentication & ATO` and the primary impact is authentication or account takeover.

