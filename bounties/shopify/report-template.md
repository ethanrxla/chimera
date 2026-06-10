# Shopify HackerOne Report Template

## Title

`[Authentication & ATO] Account A can <action> Account B <auth/account object> via <endpoint/flow>`

## Summary

Describe the root cause in one paragraph. State why the impact is authentication or account takeover related.

## Scope Confirmation

- Program: Shopify HackerOne.
- Asset: Authentication & ATO.
- Tested accounts/stores were created by the researcher.
- No live merchant or third-party data was accessed.
- Date tested: `YYYY-MM-DD`.

## Affected Surface

- Surface: `accounts.shopify.com` / Merchant Admin / Partners / Checkout / Login with Shop / other.
- Endpoint or flow: `METHOD /path`.
- Object boundary crossed: account / shop / organization / session / MFA factor / OAuth grant / recovery method.

## Steps to Reproduce

1. Log in as Account B and create or identify the target object.
2. Capture the legitimate Account B request and response.
3. Log in as Account A.
4. Replay the request with Account A credentials and Account B object identifiers.
5. Observe the unauthorized result.

## Expected Result

Account A receives `403`, `404`, or equivalent denial, and Account B state is unchanged.

## Actual Result

Account A can `REPLACE_WITH_IMPACT`.

## Evidence

```http
REPLACE_WITH_REDACTED_REQUEST_RESPONSE
```

Screenshots/artifacts:

- `bounties/shopify/artifacts/REPLACE_WITH_FILE`

## Impact

Explain the concrete authentication/account impact, such as MFA downgrade, session revocation, OAuth grant compromise, partner org access, or account takeover.

## Remediation

Bind the object/action to the authenticated user, shop, organization, OAuth client, and session context server-side. Re-check authorization on every state-changing account-management operation and invalidate stale challenges after security state changes.

