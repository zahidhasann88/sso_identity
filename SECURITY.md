# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository — open a draft advisory rather than a public issue, so the
report stays private until a fix exists.

Useful things to include: the version or commit, the configuration involved
(especially `JWT_BLACKLIST_BACKEND`, `TRUST_PROXY_HEADERS` and whether a shared
cache is configured), and the smallest request sequence that reproduces it.

Please do not include real credentials, private keys or production tokens in a
report; a locally generated keypair reproduces everything this service does.

## Scope

This is a reference implementation of a JWT identity provider, published as a
portfolio project. It is not a hosted service, so there is no production
deployment to attack and no bug bounty. Reports about the code are welcome all
the same — particularly anything that would let a caller:

- have a token accepted after it was revoked, rotated, or its user's
  `token_version` was bumped;
- get a token verified against a key the service does not publish, or with a
  symmetric algorithm;
- consume one refresh token more than once;
- read or act on a token belonging to another principal;
- evade the login lockout or the per-endpoint throttles.

## What is already known and documented

These are deliberate design positions rather than vulnerabilities, and the
reasoning is in the README:

- **Revocation is not instant for relying parties.** They verify offline from
  the JWKS, so a revoked token keeps working at a relying party until the access
  token expires — bounded by `ACCESS_TOKEN_MINUTES`. `/api/auth/introspect/` is
  the escape hatch for callers that need certainty.
- **Throttling and lockout are only as shared as the cache.** With the default
  local-memory cache and several worker processes, the limits are per-process.
  `manage.py check --deploy` reports this as `identity.W001`.
- **`metadata` supplied at registration is echoed into the access token.** It is
  caller-controlled data inside a signed token; relying parties should treat
  `meta` as a claim the user chose, not as an assertion by this service.
