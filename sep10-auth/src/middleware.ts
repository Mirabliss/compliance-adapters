/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { Request, RequestHandler } from 'express';
import { StrKey } from '@stellar/stellar-sdk';
import { type Logger, noopLogger } from '@compliance-adapters/logger';
import { verifyChallenge, VerifyChallengeOptions } from './verify';
import { RevocationStore } from './revocation';
import { assertBareDomain } from './challenge';

declare global {
  namespace Express {
    interface Request {
      stellarAddress?: string;
      /** Identifier (`jti`) of the verified token; use with `RevocationStore.revokeToken`. */
      stellarTokenId?: string;
    }
  }
}

/**
 * The result of {@link parseBearerToken}.
 *
 * A discriminated union: `ok: true` carries the extracted token; `ok: false`
 * carries a human-readable reason string explaining why parsing failed.
 */
export type ParseBearerTokenResult =
  | { ok: true; token: string }
  | { ok: false; reason: string };

/**
 * Extracts the Bearer token from a raw `Authorization` header value.
 *
 * Accepts the standard `Bearer <token>` format (scheme matching is
 * case-insensitive, as required by RFC 7235). Returns a discriminated-union
 * result rather than throwing so callers can handle errors without try/catch.
 *
 * @param header - The raw value of the `Authorization` header. Pass an empty
 *   string or `undefined` (coerced to `''`) when the header is absent.
 *
 * @returns `{ ok: true, token }` when a non-empty Bearer token was found, or
 *   `{ ok: false, reason }` for any of the following failure cases:
 *   - header is missing or empty
 *   - the scheme is not `Bearer` (case-insensitive)
 *   - the token portion is missing or empty (e.g. `"Bearer "` with trailing space only)
 *   - the header contains more than two whitespace-separated parts (malformed)
 *
 * @example
 * ```ts
 * const result = parseBearerToken(req.header('Authorization') ?? '');
 * if (!result.ok) {
 *   res.status(401).json({ error: result.reason });
 *   return;
 * }
 * // result.token is the raw base64-XDR string
 * ```
 */
export function parseBearerToken(header: string): ParseBearerTokenResult {
  if (!header) {
    return { ok: false, reason: 'missing bearer token' };
  }

  // Split on a single space only. RFC 7235 §2.1 says the token68 value is
  // a single contiguous string, so legitimate Bearer headers are exactly
  // two whitespace-separated parts. We split on the first space only so that
  // a token that itself contains spaces is never silently truncated — instead
  // it produces the correct "malformed" error.
  const spaceIndex = header.indexOf(' ');
  if (spaceIndex === -1) {
    // e.g. "Bearer" with no space at all
    return { ok: false, reason: 'missing bearer token' };
  }

  const scheme = header.slice(0, spaceIndex);
  const rest = header.slice(spaceIndex + 1);

  if (scheme.toLowerCase() !== 'bearer') {
    return { ok: false, reason: 'missing bearer token' };
  }

  // Reject trailing-space-only values and anything with embedded whitespace
  // (a valid XDR token is a single base64 string with no spaces).
  const token = rest.trim();
  if (!token) {
    return { ok: false, reason: 'missing bearer token' };
  }

  // A legitimate Bearer token must not contain internal whitespace.
  if (/\s/.test(rest)) {
    return { ok: false, reason: 'malformed bearer token' };
  }

  return { ok: true, token };
}

function parseCustomToken(token: string | undefined): ParseBearerTokenResult {
  return token ? { ok: true, token } : { ok: false, reason: 'missing bearer token' };
}

export interface Sep10MiddlewareOptions extends VerifyChallengeOptions {
  /**
   * Optional store consulted after a challenge verifies successfully, to
   * reject addresses revoked before their challenge naturally expired.
   */
  revocationStore?: RevocationStore;
  /** Optional injectable logger for observability. Nothing is logged if omitted. */
  logger?: Logger;
  /**
   * Maximum accepted length (in characters) of the bearer token, rejected
   * with 401 before XDR parsing is attempted. A signed SEP-10 challenge XDR
   * has a well-known bounded size, so this guards against unauthenticated
   * callers forcing expensive XDR-parsing work with oversized garbage input.
   * @default 8192
   */
  maxTokenLength?: number;
  /**
   * Custom token extractor, e.g. to read the token from a cookie or query
   * parameter instead of the `Authorization: Bearer` header. Return
   * `undefined` (or an empty string) when the request carries no token; the
   * request is then rejected with 401. When omitted, the token is read from
   * the `Authorization` header as a Bearer token.
   *
   * Cookie-based extraction exposes the endpoint to CSRF: browsers attach
   * cookies automatically, so pair it with SameSite cookies and/or a CSRF
   * token check.
   */
  getToken?: (req: Request) => string | undefined;
}

const DEFAULT_MAX_TOKEN_LENGTH = 8192;

/**
 * RFC 6750 §3.1 error code for a 401 response: `invalid_request` when the
 * `Authorization` header is missing or malformed, `invalid_token` when the
 * token itself was rejected.
 */
export type BearerErrorCode = 'invalid_request' | 'invalid_token';

function buildWwwAuthenticate(realm: string, error: BearerErrorCode): string {
  return `Bearer realm="${realm}", error="${error}"`;
}

/** Request headers as exposed by Node's `http` module and Fastify. */
export type RequestHeaders = Record<string, string | string[] | undefined>;

/**
 * The result of {@link authenticateRequest}.
 *
 * On failure, `wwwAuthenticate` is the RFC 6750 §3 `WWW-Authenticate` header
 * value adapters must send alongside the 401 response.
 */
export type AuthenticateRequestResult =
  | { ok: true; address: string; jti?: string }
  | {
      ok: false;
      error: BearerErrorCode;
      reason: string;
      wwwAuthenticate: string;
      logMessage: string;
      logContext?: Record<string, unknown>;
    };

/**
 * Validates the middleware options once at construction time and returns the
 * normalised home domains. Shared by every framework adapter.
 */
export function assertSep10MiddlewareOptions(options: Sep10MiddlewareOptions): string[] {
  if (!StrKey.isValidEd25519PublicKey(options.serverAccountId)) {
    throw new Error(
      `sep10-auth: Invalid serverAccountId: ${options.serverAccountId}`,
    );
  }

  const homeDomains = Array.isArray(options.homeDomains)
    ? options.homeDomains
    : [options.homeDomains];
  if (homeDomains.length === 0 || homeDomains.some((d) => !d)) {
    throw new Error('sep10-auth: homeDomains must be a non-empty array of non-empty strings');
  }
  homeDomains.forEach((d) => assertBareDomain('homeDomains', d));

  const webAuthDomains = Array.isArray(options.webAuthDomain)
    ? options.webAuthDomain
    : [options.webAuthDomain];
  if (webAuthDomains.length === 0 || webAuthDomains.some((d) => !d)) {
    throw new Error('sep10-auth: webAuthDomain must be a non-empty array of non-empty strings');
  }
  webAuthDomains.forEach((d) => assertBareDomain('webAuthDomain', d));

  return homeDomains;
}

/**
 * Verifies the `Authorization` header and signed challenge. It does not
 * consult the revocation store, so callers needing revocation checks should
 * use {@link authenticateRequest} instead.
 */
export async function verifyRequestHeaders(
  headers: RequestHeaders,
  options: Sep10MiddlewareOptions,
): Promise<AuthenticateRequestResult> {
  const maxTokenLength = options.maxTokenLength ?? DEFAULT_MAX_TOKEN_LENGTH;
  const realm = Array.isArray(options.homeDomains) ? options.homeDomains[0] : options.homeDomains;

  const fail = (
    error: BearerErrorCode,
    reason: string,
    logMessage: string,
    logContext?: Record<string, unknown>,
  ): AuthenticateRequestResult => ({
    ok: false,
    error,
    reason,
    wwwAuthenticate: buildWwwAuthenticate(realm, error),
    logMessage,
    logContext,
  });

  const rawHeader = headers.authorization ?? headers.Authorization;
  const parsed = parseBearerToken(
    (Array.isArray(rawHeader) ? rawHeader[0] : rawHeader) ?? '',
  );

  if (!parsed.ok) {
    return fail(
      'invalid_request',
      parsed.reason,
      'sep10-auth: missing or malformed bearer token',
    );
  }

  const token = parsed.token;

  if (token.length > maxTokenLength) {
    return fail(
      'invalid_token',
      'bearer token too large',
      'sep10-auth: bearer token exceeds maximum length',
      { length: token.length },
    );
  }

  const result = await verifyChallenge(token, options);

  if (!result.valid) {
    return fail(
      'invalid_token',
      result.error ?? 'invalid token',
      'sep10-auth: challenge verification failed',
      { reason: result.error },
    );
  }

  return { ok: true, address: result.address, jti: result.jti };
}

/**
 * Applies the optional revocation store to a successful
 * {@link verifyRequestHeaders} result. A failed result is returned unchanged.
 * A store lookup failure rejects, as it is an internal failure rather than an
 * authentication failure.
 */
export async function applyRevocationStore(
  result: AuthenticateRequestResult,
  options: Sep10MiddlewareOptions,
): Promise<AuthenticateRequestResult> {
  if (!result.ok || !options.revocationStore) {
    return result;
  }

  if (await options.revocationStore.isRevoked(result.address)) {
    const realm = Array.isArray(options.homeDomains) ? options.homeDomains[0] : options.homeDomains;
    return {
      ok: false,
      error: 'invalid_token',
      reason: 'address revoked',
      wwwAuthenticate: buildWwwAuthenticate(realm, 'invalid_token'),
      logMessage: 'sep10-auth: address is revoked',
      logContext: { address: result.address },
    };
  }

  return result;
}

/**
 * Framework-agnostic SEP-10 request authentication. Parses the `Authorization`
 * header, verifies the signed challenge and consults the revocation store.
 *
 * Shared by the Express middleware ({@link createSep10Middleware}) and the
 * Fastify plugin (`sep10-auth/fastify`). A thrown error (e.g. the revocation
 * store being unavailable) is an internal failure, not an authentication
 * failure, and is left for the adapter to forward to its error handler.
 */
export async function authenticateRequest(
  headers: RequestHeaders,
  options: Sep10MiddlewareOptions,
): Promise<AuthenticateRequestResult> {
  return applyRevocationStore(await verifyRequestHeaders(headers, options), options);
}

// Reference pattern only: expects the raw signed SEP-10 challenge XDR on every
// request via `Authorization: Bearer <base64-xdr>`. A production app would
// typically verify once and issue a short-lived session JWT instead of
// re-verifying the challenge transaction on every request; that is out of
// scope for this package.
export function createSep10Middleware(options: Sep10MiddlewareOptions): RequestHandler {
  const logger = options.logger ?? noopLogger;

  // ── #39: Validate required configuration at construction time ──────────────
  // Catch misconfiguration early rather than on first request.
  assertSep10MiddlewareOptions(options);

  // ── Request handler ─────────────────────────────────────────────────────────

  return async (req, res, next) => {
    let result = await verifyRequestHeaders({ authorization: req.header('Authorization') }, options);

    if (result.ok && options.revocationStore) {
      try {
        result = await applyRevocationStore(result, options);
      } catch (error) {
        logger.error('sep10-auth: revocation store lookup failed', error);
        next(error);
        return;
      }
    }

    if (!result.ok) {
      logger.warn('sep10-auth: challenge verification failed', { reason: result.reason });
      res.status(401).json({ error: 'unauthorized', reason: result.reason });
      res.set('WWW-Authenticate', result.wwwAuthenticate);
      return;
    }

    if (options.revocationStore && result.jti !== undefined && options.revocationStore.isTokenRevoked) {
      let tokenRevoked: boolean;
      try {
        tokenRevoked = await options.revocationStore.isTokenRevoked(result.jti);
      } catch (error) {
        logger.error('sep10-auth: revocation store lookup failed', error);
        next(error);
        return;
      }

      if (tokenRevoked) {
        logger.warn('sep10-auth: token is revoked', { address: result.address, jti: result.jti });
        res.status(401).json({ error: 'unauthorized', reason: 'token revoked' });
        return;
      }
    }

    logger.debug('sep10-auth: request authenticated', { address: result.address, path: req.path });
    req.stellarAddress = result.address;
    req.stellarTokenId = result.jti;
    next();
  };
}
