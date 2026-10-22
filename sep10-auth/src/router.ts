/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import type { Router } from 'express';
import { Keypair, Networks } from '@stellar/stellar-sdk';
import { type Logger, noopLogger } from '@compliance-adapters/logger';
import {
  generateChallenge,
  InvalidClientAddressError,
  InvalidDomainError,
  InvalidMemoError,
  assertBareDomain,
} from './challenge';
import { verifyChallenge, AccountLoader } from './verify';
import { issueJwt } from './jwt';
import { rateLimiter, RateLimiterOptions } from './rate-limiter';

export interface Sep10RouterOptions {
  /** Server keypair used to sign challenge transactions. Must be able to sign. */
  serverKeypair: Keypair;
  /**
   * Home domain(s) this server authenticates for. The first one is used when a
   * `GET /auth` request omits `home_domain`.
   */
  homeDomain: string | string[];
  /** Web-auth domain(s) embedded in challenges. @default the first home domain */
  webAuthDomain?: string | string[];
  /** @default Networks.TESTNET */
  networkPassphrase?: string;
  /** Challenge validity in seconds. @default 300 */
  challengeTimeoutSeconds?: number;
  /**
   * Options for the built-in {@link rateLimiter}, which guards both endpoints.
   * Pass `false` to mount the router without one.
   */
  rateLimit?: RateLimiterOptions | false;
  /** HMAC secret for the built-in JWT issuer. Required unless `issueToken` is set. */
  jwtSecret?: string | Buffer;
  /** @default 86400 */
  jwtExpiresInSeconds?: number;
  /** The JWT `iss` claim. @default `https://<first home domain>` */
  jwtIssuer?: string;
  /**
   * Replaces the built-in JWT issuer. Called with the authenticated account
   * after a challenge verifies successfully.
   */
  issueToken?: (
    account: string,
    context: { clientDomain?: string; transaction: string },
  ) => string | Promise<string>;
  /**
   * Resolves the `SIGNING_KEY` published on `<clientDomain>/.well-known/stellar.toml`.
   * Without it, `GET /auth` rejects requests carrying a `client_domain`.
   */
  resolveClientSigningKey?: (clientDomain: string) => string | Promise<string>;
  /** Maximum accepted length of the posted transaction. @default 8192 */
  maxTransactionLength?: number;
  /**
   * Optional account loader for on-ledger signer / threshold verification of
   * the client account during `POST /auth` challenge verification. When
   * provided, the challenge signatures are verified against the account's
   * on-ledger signer set and medium threshold (SEP-10 for existing accounts).
   * When the account doesn't exist on the ledger, falls back to the master-key
   * check. See {@link verifyChallenge}'s `accountLoader` option for details.
   */
  accountLoader?: AccountLoader;
  logger?: Logger;
}

const DEFAULT_MAX_TRANSACTION_LENGTH = 8192;

function firstString(value: unknown): string | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  return typeof v === 'string' && v !== '' ? v : undefined;
}

/**
 * Creates an Express Router implementing the two SEP-10 endpoints:
 *
 * - `GET /auth?account=...&home_domain=...&client_domain=...&memo=...`
 *   responds `{ transaction, network_passphrase }`.
 * - `POST /auth` with `{ transaction }` (JSON or form-encoded) responds
 *   `{ token }`.
 *
 * Failures respond with `{ error: "<message>" }` as SEP-10 requires: `400` for
 * invalid requests and challenges, `429` from the rate limiter.
 *
 * @example
 * ```ts
 * app.use(createSep10Router({
 *   serverKeypair,
 *   homeDomain: 'example.com',
 *   jwtSecret: process.env.SEP10_JWT_SECRET!,
 * }));
 * ```
 */
export function createSep10Router(options: Sep10RouterOptions): Router {
  const logger = options.logger ?? noopLogger;
  const homeDomains = Array.isArray(options.homeDomain) ? options.homeDomain : [options.homeDomain];
  if (homeDomains.length === 0 || homeDomains.some((d) => !d)) {
    throw new Error('sep10-auth: homeDomain must be a non-empty array of non-empty strings');
  }
  homeDomains.forEach((d) => assertBareDomain('homeDomain', d));

  const webAuthDomain = options.webAuthDomain ?? homeDomains[0];
  const webAuthDomains = Array.isArray(webAuthDomain) ? webAuthDomain : [webAuthDomain];
  if (webAuthDomains.length === 0 || webAuthDomains.some((d) => !d)) {
    throw new Error('sep10-auth: webAuthDomain must be a non-empty array of non-empty strings');
  }
  webAuthDomains.forEach((d) => assertBareDomain('webAuthDomain', d));

  if (!options.serverKeypair.canSign()) {
    throw new Error('sep10-auth: serverKeypair must be able to sign');
  }
  if (!options.issueToken && !options.jwtSecret) {
    throw new Error('sep10-auth: either jwtSecret or issueToken must be provided');
  }

  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET;
  const maxTransactionLength = options.maxTransactionLength ?? DEFAULT_MAX_TRANSACTION_LENGTH;
  const issueToken =
    options.issueToken ??
    ((account, context) =>
      issueJwt({
        secret: options.jwtSecret as string | Buffer,
        issuer: options.jwtIssuer ?? `https://${homeDomains[0]}`,
        subject: account,
        expiresInSeconds: options.jwtExpiresInSeconds,
        jtiSource: context.transaction,
        clientDomain: context.clientDomain,
      }));

  // express is an optional peer dependency; load it only when a router is
  // actually built so importing this package never requires it.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const express = require('express') as typeof import('express');
  const router = express.Router();

  if (options.rateLimit !== false) {
    router.use('/auth', rateLimiter(options.rateLimit ?? {}));
  }
  router.use('/auth', express.json(), express.urlencoded({ extended: false }));

  router.get('/auth', async (req, res, next) => {
    try {
      const account = firstString(req.query.account);
      if (!account) {
        res.status(400).json({ error: 'missing required "account" query parameter' });
        return;
      }

      const homeDomain = firstString(req.query.home_domain) ?? homeDomains[0];
      if (!homeDomains.includes(homeDomain)) {
        res.status(400).json({ error: 'invalid "home_domain" query parameter' });
        return;
      }

      const memo = firstString(req.query.memo);
      const clientDomain = firstString(req.query.client_domain);
      let clientSigningKey: string | undefined;
      if (clientDomain) {
        if (!options.resolveClientSigningKey) {
          res.status(400).json({ error: '"client_domain" is not supported' });
          return;
        }
        try {
          assertBareDomain('client_domain', clientDomain);
          clientSigningKey = await options.resolveClientSigningKey(clientDomain);
        } catch (error) {
          logger.warn('sep10-auth: could not resolve client_domain signing key', {
            clientDomain,
            error,
          });
          res.status(400).json({ error: 'invalid "client_domain" query parameter' });
          return;
        }
      }

      const challenge = generateChallenge(account, options.serverKeypair, {
        homeDomain,
        webAuthDomain: webAuthDomains.includes(homeDomain) ? homeDomain : webAuthDomains[0],
        networkPassphrase,
        timeoutSeconds: options.challengeTimeoutSeconds,
        memo,
        clientDomain,
        clientSigningKey,
        logger,
      });

      res.json({
        transaction: challenge.transactionXDR,
        network_passphrase: challenge.networkPassphrase,
      });
    } catch (error) {
      if (error instanceof InvalidClientAddressError) {
        res.status(400).json({ error: 'invalid "account" query parameter' });
        return;
      }
      if (error instanceof InvalidMemoError) {
        res.status(400).json({ error: 'invalid "memo" query parameter' });
        return;
      }
      if (error instanceof InvalidDomainError) {
        res.status(400).json({ error: 'invalid domain parameter' });
        return;
      }
      next(error);
    }
  });

  router.post('/auth', async (req, res, next) => {
    try {
      const transaction = firstString(req.body?.transaction);
      if (!transaction) {
        res.status(400).json({ error: 'missing required "transaction" parameter' });
        return;
      }
      if (transaction.length > maxTransactionLength) {
        res.status(400).json({ error: '"transaction" is too large' });
        return;
      }

      const result = await verifyChallenge(transaction, {
        serverAccountId: options.serverKeypair.publicKey(),
        networkPassphrase,
        homeDomains,
        webAuthDomain: webAuthDomains,
        ...(options.accountLoader ? { accountLoader: options.accountLoader } : {}),
      });

      if (!result.valid) {
        logger.warn('sep10-auth: challenge verification failed', { reason: result.error });
        res.status(400).json({ error: result.error ?? 'invalid challenge transaction' });
        return;
      }

      const token = await issueToken(result.address, {
        clientDomain: result.clientDomain,
        transaction,
      });
      res.json({ token });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
