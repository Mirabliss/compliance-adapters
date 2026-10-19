/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { createHash, createHmac } from 'crypto';

export interface IssueJwtOptions {
  /** HMAC secret used to sign the token (HS256). */
  secret: string | Buffer;
  /** The `iss` claim: a URI identifying the issuer, e.g. `https://example.com`. */
  issuer: string;
  /** The authenticated Stellar account (the `sub` claim). */
  subject: string;
  /** Token lifetime in seconds. @default 86400 */
  expiresInSeconds?: number;
  /** The `jti` claim. Defaults to the SHA-256 hex digest of `jtiSource`. */
  jtiSource?: string;
  /** The wallet's client domain, copied into the `client_domain` claim when set. */
  clientDomain?: string;
  /** Current time in milliseconds since the epoch. Injectable for tests. */
  now?: number;
}

const DEFAULT_EXPIRES_IN_SECONDS = 24 * 60 * 60;

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

/**
 * Issues a SEP-10 session JWT (HS256) for an authenticated Stellar account.
 *
 * The claims follow SEP-10 §Token: `iss`, `sub`, `iat`, `exp`, `jti` and the
 * optional `client_domain`.
 */
export function issueJwt(options: IssueJwtOptions): string {
  const iat = Math.floor((options.now ?? Date.now()) / 1000);
  const claims: Record<string, unknown> = {
    iss: options.issuer,
    sub: options.subject,
    iat,
    exp: iat + (options.expiresInSeconds ?? DEFAULT_EXPIRES_IN_SECONDS),
    jti: createHash('sha256')
      .update(options.jtiSource ?? `${options.subject}:${iat}`)
      .digest('hex'),
  };
  if (options.clientDomain) {
    claims.client_domain = options.clientDomain;
  }

  const signingInput = `${base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${base64url(
    JSON.stringify(claims),
  )}`;
  const signature = createHmac('sha256', options.secret).update(signingInput).digest();
  return `${signingInput}.${base64url(signature)}`;
}
