---
'sep10-auth': minor
---

- `createSep10Middleware` now sets an RFC 6750 `WWW-Authenticate: Bearer realm="<homeDomain>", error="invalid_request" | "invalid_token"` header on every `401` response.
- `rateLimiter` gains a `standardHeaders` option (default `true`) that sends the IETF `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` headers on allowed and throttled responses.
- Extract the framework-agnostic `authenticateRequest(headers, options)` and add the optional `sep10-auth/fastify` plugin (`fastify` and `fastify-plugin` are optional peer dependencies) that decorates `request.stellarAddress`.
- Add `createSep10Router(options)`, an Express router exposing spec-compliant `GET /auth` and `POST /auth`, with a built-in `issueJwt` HS256 token issuer. The Express example app now uses it.
