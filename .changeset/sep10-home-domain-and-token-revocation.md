---
'sep10-auth': minor
---

Add `resolveHomeDomain(requested, configured)` and `UnknownHomeDomainError`:
a missing `home_domain` falls back to the first configured domain and an
unknown one is rejected (the example router now returns 400 for it).

`RevocationStore` gains optional `revokeToken(jti, expiresAt)` /
`isTokenRevoked(jti)` for per-token revocation alongside per-address
revocation. `verifyChallenge` now returns a `jti` (the challenge transaction
hash) and the middleware sets `req.stellarTokenId`, rejecting revoked tokens
with 401 `token revoked`. `InMemoryRevocationStore` implements both and
prunes expired token revocations.
