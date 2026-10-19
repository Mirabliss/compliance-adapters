import express from 'express';
import { randomBytes } from 'crypto';
import { Keypair, Networks } from '@stellar/stellar-sdk';
import {
  generateChallenge,
  createSep10Middleware,
  resolveHomeDomain,
  UnknownHomeDomainError,
} from '../../src';

export interface ExampleAppOptions {
  /**
   * Server keypair used to sign challenge transactions. A real deployment loads
   * this from a secret store and keeps it stable across restarts, since the
   * public key is the server account clients authenticate against. Defaults to
   * a fresh random keypair — fine for a demo, not for a deployment.
   */
  serverKeypair?: Keypair;
  homeDomain?: string;
  /**
   * Home domains this server serves. A client selects one with the SEP-10
   * `home_domain` query parameter; unknown values are rejected with 400 and a
   * missing value falls back to the first entry. Defaults to `[homeDomain]`.
   */
  homeDomains?: string[];
  webAuthDomain?: string;
  networkPassphrase?: string;
  /** HMAC secret for the session JWT returned by `POST /auth`. Defaults to a random demo secret. */
  jwtSecret?: string;
}

export interface ExampleApp {
  app: express.Express;
  serverKeypair: Keypair;
}

/**
 * Build the SEP-10 example Express app without binding to a port.
 *
 * Keeping app construction separate from server startup (see `server.ts`) makes
 * the routes testable with supertest — mirroring the `createApp()` pattern used
 * by `examples/sep10-sanctions-gate`.
 */
export function createApp(options: ExampleAppOptions = {}): ExampleApp {
  const serverKeypair = options.serverKeypair ?? Keypair.random();
  const homeDomain = options.homeDomain ?? 'example.com';
  const homeDomains = options.homeDomains ?? [homeDomain];
  const webAuthDomain = options.webAuthDomain ?? homeDomains[0];
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET;

  const app = express();
  app.use(express.json());

  // Step 1: client requests a challenge transaction for its address to sign.
  app.get('/challenge', (req, res) => {
    const clientAddress = req.query.address;

    if (typeof clientAddress !== 'string' || !clientAddress) {
      res.status(400).json({ error: 'missing required "address" query parameter' });
      return;
    }

    const requestedHomeDomain = req.query.home_domain;
    let resolvedHomeDomain: string;
    try {
      resolvedHomeDomain = resolveHomeDomain(
        typeof requestedHomeDomain === 'string' ? requestedHomeDomain : undefined,
        homeDomains,
      );
    } catch (error) {
      if (error instanceof UnknownHomeDomainError) {
        res.status(400).json({ error: 'unknown "home_domain" query parameter' });
        return;
      }
      throw error;
    }

    try {
      const challenge = generateChallenge(clientAddress, serverKeypair, {
        homeDomain: resolvedHomeDomain,
        webAuthDomain,
        networkPassphrase,
      });

      res.json({
        transaction: challenge.transactionXDR,
        network_passphrase: challenge.networkPassphrase,
      });
    } catch {
      res.status(400).json({ error: 'invalid "address" query parameter' });
    }
  });

  // Step 2: the client signs the challenge with its own wallet and sends the signed
  // XDR back as a bearer token on any protected route.
  app.get(
    '/protected',
    createSep10Middleware({
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase,
      homeDomains,
      webAuthDomain,
    }),
    (req, res) => {
      res.json({ address: req.stellarAddress });
    },
  );

  return { app, serverKeypair };
}
