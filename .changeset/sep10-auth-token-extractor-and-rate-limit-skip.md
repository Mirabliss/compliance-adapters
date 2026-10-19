---
'sep10-auth': minor
---

`createSep10Middleware` accepts an optional `getToken(req)` to extract the token
from somewhere other than the `Authorization: Bearer` header (e.g. a cookie);
default behaviour is unchanged. `rateLimiter` accepts an optional `skip(req)`
predicate (sync or async) whose skipped requests never consume tokens.
