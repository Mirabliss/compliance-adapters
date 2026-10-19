/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { Keypair, Networks, StrKey, WebAuth } from '@stellar/stellar-sdk';
import { type Logger, noopLogger } from '@compliance-adapters/logger';
import { isValidStellarAddress } from '@compliance-adapters/shared';

export class InvalidClientAddressError extends Error {
  constructor(address: string) {
    super(`Invalid client address: ${address}`);
    this.name = 'InvalidClientAddressError';
  }
}

export class InvalidMemoError extends Error {
  constructor(memo: string) {
    super(`Invalid memo: "${memo}" must be a numeric string representing a 64-bit unsigned integer`);
    this.name = 'InvalidMemoError';
  }
}

export class MemoWithMuxedAccountError extends Error {
  constructor() {
    super(
      'sep10-auth: a memo cannot be combined with a muxed (M...) client account; SEP-10 identifies the sub-user by the mux id instead',
    );
    this.name = 'MemoWithMuxedAccountError';
  }
}

export class InvalidTimeoutError extends Error {
  constructor(value: number) {
    super(
      `sep10-auth: timeoutSec must be a finite number greater than 0 and at most ${MAX_TIMEOUT_SECONDS}, got ${value}`,
    );
    this.name = 'InvalidTimeoutError';
  }
}

export class InvalidDomainError extends Error {
  constructor(name: string, value: string) {
    super(
      `sep10-auth: ${name} must be a bare domain (no scheme, path, or whitespace), got "${value}"`,
    );
    this.name = 'InvalidDomainError';
  }
}

export class UnknownHomeDomainError extends Error {
  constructor(requested: string, configured: string[]) {
    super(
      `sep10-auth: unknown home_domain "${requested}"; must be one of: ${configured.join(', ')}`,
    );
    this.name = 'UnknownHomeDomainError';
  }
}

export class ServerKeypairCannotSignError extends Error {
  constructor() {
    super(
      'sep10-auth: serverKeypair cannot sign — provide a keypair with a secret key, not a public-key-only keypair',
    );
    this.name = 'ServerKeypairCannotSignError';
  }
}

const MAX_UINT64 = 2n ** 64n - 1n;

/** Upper bound (seconds) enforced on the challenge validity window. */
export const MAX_TIMEOUT_SECONDS = 3600;

/**
 * Throws {@link InvalidDomainError} when `value` is not a bare domain, i.e. it
 * contains a URL scheme (`://`), a `/`, or whitespace, as SEP-10 requires for
 * `home_domain` and `web_auth_domain`.
 */
export function assertBareDomain(name: string, value: string): void {
  if (/:\/\/|\/|\s/.test(value)) {
    throw new InvalidDomainError(name, value);
  }
}

/**
 * Resolves the SEP-10 `home_domain` request parameter against the configured
 * home domains. A missing or empty `requested` value falls back to the first
 * configured domain; any other value must exactly match a configured domain.
 *
 * @throws {@link UnknownHomeDomainError} when `requested` is not configured —
 *   callers should respond with HTTP 400, as SEP-10 recommends.
 */
export function resolveHomeDomain(
  requested: string | null | undefined,
  configured: string | string[],
): string {
  const domains = Array.isArray(configured) ? configured : [configured];
  if (domains.length === 0) {
    throw new Error('sep10-auth: configured home domains must not be empty');
  }
  if (requested === undefined || requested === null || requested === '') {
    return domains[0];
  }
  if (!domains.includes(requested)) {
    throw new UnknownHomeDomainError(requested, domains);
  }
  return requested;
}

export interface GenerateChallengeOptions {
  homeDomain?: string;
  webAuthDomain?: string;
  networkPassphrase?: string;
  /**
   * Challenge validity window in seconds. Must be finite, greater than 0 and at
   * most {@link MAX_TIMEOUT_SECONDS} (3600); otherwise {@link InvalidTimeoutError}
   * is thrown. Defaults to 900.
   */
  timeoutSec?: number;
  /** @deprecated Alias of {@link GenerateChallengeOptions.timeoutSec}; `timeoutSec` wins when both are set. */
  timeoutSeconds?: number;
  memo?: string | null;
  /**
   * The wallet's client domain, as supplied in the SEP-10 `client_domain`
   * request parameter. When set, the challenge transaction includes an
   * additional `client_domain` ManageData operation (sourced from
   * {@link GenerateChallengeOptions.clientSigningKey}) that the wallet's
   * client-domain server must co-sign alongside the client's own key.
   * Requires {@link GenerateChallengeOptions.clientSigningKey} to also be set.
   */
  clientDomain?: string;
  /**
   * The `SIGNING_KEY` published on `<clientDomain>/.well-known/stellar.toml`.
   * The caller is responsible for resolving this value; this package does not
   * fetch stellar.toml itself. Required when {@link GenerateChallengeOptions.clientDomain} is set.
   */
  clientSigningKey?: string;
  logger?: Logger;
}

/**
 * The result of {@link generateChallenge}.
 */
export interface GeneratedChallenge {
  /** Base64-encoded XDR of the unsigned (server-signed only) challenge transaction, to be sent to the client for signing. */
  transactionXDR: string;
  /** The network passphrase the challenge transaction was built for. Must be passed back into {@link verifyChallenge} unchanged. */
  networkPassphrase: string;
  /** When the challenge stops being valid, derived from `timeoutSec`. A signed challenge submitted after this time will fail verification. */
  expiresAt: Date;
}

const DEFAULT_HOME_DOMAIN = 'localhost:3000';
const DEFAULT_TIMEOUT_SECONDS = 900;

/** Accepts a `G...` account or a muxed `M...` account as the SEP-10 client account. */
function isValidClientAddress(address: string): boolean {
  return isValidStellarAddress(address) || StrKey.isValidMed25519PublicKey(address);
}

/**
 * Builds a SEP-10 challenge. `clientAddress` may be a `G...` account or a muxed
 * `M...` account (SEP-10 v3); a muxed account cannot be combined with `memo`
 * ({@link MemoWithMuxedAccountError}).
 */
// Takes the server's Keypair (not just its public address) because building
// and signing the SEP-10 challenge transaction requires the server's secret key.
export function generateChallenge(
  clientAddress: string,
  serverKeypair: Keypair,
  options: GenerateChallengeOptions = {},
): GeneratedChallenge {
  if (!serverKeypair.canSign()) {
    throw new ServerKeypairCannotSignError();
  }

  if (!isValidClientAddress(clientAddress)) {
    throw new InvalidClientAddressError(clientAddress);
  }

  const logger = options.logger ?? noopLogger;
  const homeDomain = options.homeDomain ?? DEFAULT_HOME_DOMAIN;
  const webAuthDomain = options.webAuthDomain ?? homeDomain;

  if (!options.homeDomain && process.env.NODE_ENV === 'production') {
    logger.warn(
      `sep10-auth: generateChallenge is using the default homeDomain "${DEFAULT_HOME_DOMAIN}" ` +
        'in a production environment. Pass an explicit `homeDomain` option matching your deployed domain.',
      { homeDomain: DEFAULT_HOME_DOMAIN },
    );
  }
  assertBareDomain('homeDomain', homeDomain);
  assertBareDomain('webAuthDomain', webAuthDomain);

  if (options.memo != null && clientAddress.startsWith('M')) {
    throw new MemoWithMuxedAccountError();
  }

  if (options.memo != null && (!/^\d+$/.test(options.memo) || BigInt(options.memo) > MAX_UINT64)) {
    throw new InvalidMemoError(options.memo);
  }

  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET;
  const timeoutSeconds = options.timeoutSec ?? options.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0 || timeoutSeconds > MAX_TIMEOUT_SECONDS) {
    throw new InvalidTimeoutError(timeoutSeconds);
  }

  logger.debug('sep10-auth: generating challenge', { clientAddress, homeDomain, webAuthDomain });

  const transactionXDR = WebAuth.buildChallengeTx(
    serverKeypair,
    clientAddress,
    homeDomain,
    timeoutSeconds,
    networkPassphrase,
    webAuthDomain,
    options.memo ?? null,
    options.clientDomain ?? null,
    options.clientSigningKey ?? null,
  );

  const expiresAt = new Date(Date.now() + timeoutSeconds * 1000);
  logger.info('sep10-auth: challenge generated', { clientAddress, expiresAt });

  return {
    transactionXDR,
    networkPassphrase,
    expiresAt,
  };
}
