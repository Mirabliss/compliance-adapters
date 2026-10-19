import express from 'express';
import { randomBytes } from 'crypto';
import { Keypair, Networks } from '@stellar/stellar-sdk';
import { createSep10Router, createSep10Middleware } from '../../src';

export interface ExampleAppOptions {
  /**
   * Server keypair used to sign challenge transactions. A real deployment loads
   * this from a secret store and keeps it stable across restarts, since the
   * public key is the server account clients authenticate against. Defaults to
   * a fresh random keypair — fine for a demo, not for a deployment.
   */
  serverKeypair?: Keypair;
  homeDomain?: string;
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
  const webAuthDomain = options.webAuthDomain ?? homeDomain;
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET;

  const app = express();
  app.use(express.json());

  // Step 1: the router exposes the SEP-10 endpoints. GET /auth returns a
  // challenge transaction for the client to sign; POST /auth exchanges the
  // signed challenge for a session token.
  app.use(
    createSep10Router({
      serverKeypair,
      homeDomain,
      webAuthDomain,
      networkPassphrase,
      jwtSecret: options.jwtSecret ?? randomBytes(32).toString('hex'),
    }),
  );

  // Step 2: the client signs the challenge with its own wallet and sends the signed
  // XDR back as a bearer token on any protected route.
  app.get(
    '/protected',
    createSep10Middleware({
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase,
      homeDomains: homeDomain,
      webAuthDomain,
    }),
    (req, res) => {
      res.json({ address: req.stellarAddress });
    },
  );

  return { app, serverKeypair };
}
