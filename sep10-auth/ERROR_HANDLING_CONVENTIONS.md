# Error Handling Conventions — sep10-auth

All HTTP error responses from `sep10-auth` components (middleware, rate limiter, router) share a
single JSON body shape so clients can handle errors uniformly without special-casing each component.

## Standard error body

```ts
interface Sep10ErrorBody {
  /** Human-readable message — for developers, may change between releases. */
  error: string;
  /** Machine-readable code — stable across releases, safe for programmatic branching. */
  code: Sep10ErrorCode;
  /** Optional structured context (shape is code-specific, see table below). */
  details?: Record<string, unknown>;
}
```

Example:

```json
{
  "error": "unauthorized",
  "code": "invalid_token",
  "details": { "reason": "Transaction has expired" }
}
```

## Error codes

| `code`                      | HTTP | Producer        | Meaning                                                                 |
|-----------------------------|------|-----------------|-------------------------------------------------------------------------|
| `missing_token`             | 401  | middleware      | `Authorization` header absent or the scheme is not `Bearer`             |
| `malformed_token`           | 401  | middleware      | Bearer token present but contains internal whitespace                   |
| `token_too_large`           | 401  | middleware      | Bearer token exceeds the configured `maxTokenLength` (default 8 192 B)  |
| `invalid_token`             | 401  | middleware      | Token failed SEP-10 challenge verification                              |
| `token_revoked`             | 401  | middleware      | The Stellar address or the specific token `jti` has been revoked        |
| `rate_limit_exceeded`       | 429  | rate-limiter    | Client sent too many requests; `details.retryAfter` is seconds to wait  |
| `missing_account`           | 400  | router `GET`    | Required `account` query parameter is absent                            |
| `invalid_account`           | 400  | router `GET`    | `account` is not a valid Stellar G-address                              |
| `invalid_home_domain`       | 400  | router `GET`    | `home_domain` is not configured on this server                          |
| `client_domain_unsupported` | 400  | router `GET`    | `client_domain` supplied but no resolver was configured                 |
| `invalid_client_domain`     | 400  | router `GET`    | `client_domain` TOML signing key could not be resolved                  |
| `invalid_memo`              | 400  | router `GET`    | `memo` is not a valid numeric memo                                      |
| `invalid_domain`            | 400  | router `GET`    | A domain parameter failed bare-domain validation                        |
| `missing_transaction`       | 400  | router `POST`   | Required `transaction` body field is absent                             |
| `transaction_too_large`     | 400  | router `POST`   | `transaction` XDR exceeds the configured `maxTransactionLength`         |
| `invalid_transaction`       | 400  | router `POST`   | Challenge XDR failed SEP-10 verification                                |

## Client usage

Branch on `code`, not on `error` (the human-readable message may change):

```ts
const body: Sep10ErrorBody = await res.json();

switch (body.code) {
  case 'missing_token':
  case 'malformed_token':
    // redirect user to re-authenticate
    break;
  case 'token_revoked':
    // clear local session, prompt for fresh login
    break;
  case 'rate_limit_exceeded':
    // back off for body.details?.retryAfter seconds
    const retryAfter = (body.details?.retryAfter as number) ?? 60;
    await sleep(retryAfter * 1000);
    break;
  default:
    // unexpected error — surface to user or report to Sentry
}
```

## Additional headers

| Condition                     | Header                  | Value                                        |
|-------------------------------|-------------------------|----------------------------------------------|
| Any 401 from the middleware   | `WWW-Authenticate`      | `Bearer realm="<domain>", error="<rfc6750>"` |
| 429 from the rate limiter     | `Retry-After`           | Seconds until the window resets              |
| Allowed request               | `RateLimit-Limit`       | Configured max requests per window           |
| Allowed request               | `RateLimit-Remaining`   | Requests left in the current window          |
| Allowed request               | `RateLimit-Reset`       | Seconds until the window resets              |

The `WWW-Authenticate` `error` field is the RFC 6750 §3.1 token:
- `invalid_request` — header absent or not a Bearer scheme (`missing_token`, `malformed_token`)
- `invalid_token` — token present but rejected (`token_too_large`, `invalid_token`, `token_revoked`)
