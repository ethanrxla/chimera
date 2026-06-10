# Shopify Viable Attack Vectors

This plan prioritizes authentication and account-management bugs because those are campaign-multiplied through June 26, 2026.

## Priority 1: Cross-Account Authorization on Auth APIs

Goal: use Account A credentials against Account B account-management objects and confirm every response is denied.

Targets to identify in browser/Burp/Chimera traces:

- MFA factor list, creation, deletion, recovery, and challenge endpoints.
- Recovery email and phone-number update endpoints.
- Session list, session revoke, and device-management endpoints.
- OAuth grant list/revoke endpoints.
- Partner organization membership and invite endpoints.
- Merchant admin staff/account settings endpoints.

Checks:

- Replace user IDs, organization IDs, shop IDs, session IDs, grant IDs, MFA factor IDs, recovery IDs, and invite IDs with Account B values.
- Replay with Account A cookies/tokens.
- Verify `403`, `404`, or equivalent denial with no state change.
- Confirm no cross-account metadata leaks in errors.

Impact patterns worth reporting:

- Account A disables or downgrades Account B MFA.
- Account A adds, removes, or changes Account B recovery methods.
- Account A revokes or creates sessions for Account B.
- Account A approves, modifies, or revokes OAuth grants for Account B.
- Account A joins, administers, or modifies a partner org/shop they do not own.

## Priority 2: OAuth and App Authorization Flows

Goal: prove authentication impact, not just generic OAuth hygiene.

Owned setup:

- Create two Shopify development stores.
- Create a test partner organization and test app if available.
- Install the test app into Store A and Store B.
- Capture authorization redirects, callback parameters, app install flows, and token exchange endpoints.

Checks:

- Cross-store install confusion: can Store A authorization complete for Store B?
- Authorization-code substitution: can a code issued to one account/store/app be redeemed in another context?
- Login CSRF with impact: can Account A force Account B to bind an OAuth grant, app, or account link controlled by Account A?
- Scope confusion: can lower scopes become higher scopes during reauth, app update, or embedded app session issuance?
- Redirect or state bugs only matter here if they lead to token theft, account linking, app installation, or session creation.

## Priority 3: Session Token Issuance and Context Confusion

Goal: verify that Admin, Storefront, app, and checkout session tokens are audience-bound, shop-bound, user-bound, and not swappable.

Checks:

- Replay Admin tokens against Storefront/app/checkout endpoints.
- Replay Store A tokens against Store B endpoints.
- Change `shop`, `host`, `return_to`, `redirect`, `aud`, `iss`, `sub`, `sid`, and organization context parameters where present.
- Test whether logout, password change, MFA enablement, and recovery events invalidate existing sessions.
- Inspect JWT-like tokens for unsigned, weakly signed, missing audience, missing expiry, or algorithm confusion behavior before doing any live replay.

Reportable outcomes:

- Token accepted by the wrong audience.
- Token accepted for the wrong shop or organization.
- Token remains valid after a security event that should revoke it.
- Session creation without completing the expected auth or MFA flow.

## Priority 4: MFA and Recovery Flow Bypass

Goal: demonstrate bypass/downgrade with your own accounts only.

Checks:

- Enroll MFA on Account B, then attempt login, recovery, and session creation with incomplete or stale challenges.
- Test challenge replay, recovery code reuse, factor deletion race, backup method downgrade, and remember-device context confusion.
- Verify challenge IDs cannot be swapped between accounts, devices, browsers, or sessions.
- Confirm recovery flow does not expose tokens before proof completion.
- Confirm switching between email, password, SSO, recovery, and MFA steps cannot skip required state.

Avoid:

- Guessing OTPs or recovery codes at scale.
- Reporting account enumeration only.

## Priority 5: Partners Dashboard and B2B SSO/SAML

Goal: focus on organization boundary errors and login binding bugs.

Checks:

- Partner org invitations: invite ID reuse, role escalation, cross-org invite acceptance, stale invite acceptance after revoke.
- Staff or collaborator auth: cross-store role changes, permission template confusion, acceptance while logged into the wrong account.
- SAML/SSO setup: ACS URL, entity ID, relay state, tenant binding, just-in-time provisioning, domain-claim boundaries.
- SCIM, if accessible: cross-tenant user create/update/deactivate with IDs from another org.

Reportable outcomes:

- Account takeover or privilege escalation in another owned test org/store.
- Unauthorized modification of SSO, SAML, SCIM, staff, or partner settings.
- Authentication as a different user or into the wrong organization.

## Priority 6: Checkout Authentication

Goal: find authentication/session boundary issues without touching real customers.

Owned setup:

- Use your own development store.
- Create test products and test customer accounts only if customer storefront testing is eligible for the specific surface.
- Prefer checkout auth surfaces explicitly tied to the campaign.

Checks:

- Login with Shop session binding.
- Checkout account identity switches after cart/session transitions.
- Session fixation across checkout login/logout.
- Token leakage in redirect, callback, or post-auth URLs.

Note: customer storefront accounts are not campaign-multiplier eligible. Keep any report anchored to covered checkout authentication impact.

## Good First Chimera Hypotheses

- "Can an authenticated Account A revoke Account B sessions by swapping session IDs?"
- "Can an OAuth authorization code issued for Store A be redeemed in Store B app context?"
- "Can an MFA challenge created before factor removal still complete after factor state changes?"
- "Can a Partner invitation be accepted while authenticated as a different account than the invited email?"
- "Can Admin app session tokens be accepted after changing `shop` or `host` context?"

