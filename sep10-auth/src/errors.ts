/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * All machine-readable error codes produced by sep10-auth components.
 *
 * | Code                       | HTTP | Producer        | Meaning                                                    |
 * |----------------------------|------|-----------------|------------------------------------------------------------|
 * | `missing_token`            | 401  | middleware      | `Authorization` header absent or not a Bearer token        |
 * | `malformed_token`          | 401  | middleware      | Bearer token present but structurally invalid              |
 * | `token_too_large`          | 401  | middleware      | Bearer token exceeds the configured `maxTokenLength`       |
 * | `invalid_token`            | 401  | middleware      | Token failed SEP-10 challenge verification                 |
 * | `token_revoked`            | 401  | middleware      | Token or address has been explicitly revoked               |
 * | `rate_limit_exceeded`      | 429  | rate-limiter    | Client has sent too many requests in the current window    |
 * | `missing_account`          | 400  | router GET      | Required `account` query parameter absent                  |
 * | `invalid_account`          | 400  | router GET      | `account` is not a valid Stellar G-address                 |
 * | `invalid_home_domain`      | 400  | router GET      | `home_domain` value is not configured on this server       |
 * | `client_domain_unsupported`| 400  | router GET      | `client_domain` supplied but no resolver configured        |
 * | `invalid_client_domain`    | 400  | router GET      | `client_domain` signing key could not be resolved          |
 * | `invalid_memo`             | 400  | router GET      | `memo` parameter is not a valid numeric memo               |
 * | `invalid_domain`           | 400  | router GET      | A domain parameter failed bare-domain validation           |
 * | `missing_transaction`      | 400  | router POST     | Required `transaction` body parameter absent               |
 * | `transaction_too_large`    | 400  | router POST     | `transaction` XDR exceeds the configured max length        |
 * | `invalid_transaction`      | 400  | router POST     | Challenge XDR failed SEP-10 verification                   |
 */
export type Sep10ErrorCode =
  // middleware
  | 'missing_token'
  | 'malformed_token'
  | 'token_too_large'
  | 'invalid_token'
  | 'token_revoked'
  // rate-limiter
  | 'rate_limit_exceeded'
  // router — GET /auth
  | 'missing_account'
  | 'invalid_account'
  | 'invalid_home_domain'
  | 'client_domain_unsupported'
  | 'invalid_client_domain'
  | 'invalid_memo'
  | 'invalid_domain'
  // router — POST /auth
  | 'missing_transaction'
  | 'transaction_too_large'
  | 'invalid_transaction';

/**
 * Standardized JSON error body returned by all sep10-auth components.
 *
 * Every error response from the middleware, rate limiter, and router uses
 * this shape so clients can handle errors uniformly without special-casing
 * each component.
 *
 * @example
 * ```json
 * {
 *   "error": "Bearer token has expired",
 *   "code": "invalid_token",
 *   "details": { "reason": "Transaction has expired" }
 * }
 * ```
 */
export interface Sep10ErrorBody {
  /**
   * Human-readable error message. This text is intended for developers and
   * may change between releases; do not build logic on this string. Use
   * `code` for programmatic branching instead.
   */
  error: string;
  /**
   * Machine-readable error code. Stable across releases; safe to use in
   * client error-handling logic. See {@link Sep10ErrorCode} for the full list.
   */
  code: Sep10ErrorCode;
  /**
   * Optional structured context that provides extra information about the
   * error (e.g. the field that failed validation or the retry window). The
   * shape is code-specific and documented alongside each {@link Sep10ErrorCode}.
   */
  details?: Record<string, unknown>;
}

/**
 * Constructs a {@link Sep10ErrorBody} object.
 *
 * @param error   Human-readable message.
 * @param code    Machine-readable {@link Sep10ErrorCode}.
 * @param details Optional structured context.
 */
export function makeErrorBody(
  error: string,
  code: Sep10ErrorCode,
  details?: Record<string, unknown>,
): Sep10ErrorBody {
  const body: Sep10ErrorBody = { error, code };
  if (details !== undefined) body.details = details;
  return body;
}
