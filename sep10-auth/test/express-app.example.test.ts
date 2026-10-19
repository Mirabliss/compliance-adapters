/// <reference types="jest" />

/**
 * Boots the SEP-10 Express example (examples/express-app) via its extracted
 * createApp() factory and exercises the documented routes with supertest —
 * no real port binding, no live Stellar network.
 *
 * This guards the example against silently breaking if the sep10-auth API it
 * demonstrates changes upstream (see issue #346).
 */

import request from 'supertest';
import { Keypair, Networks, Transaction } from '@stellar/stellar-sdk';
import { createApp } from '../examples/express-app/app';

const HOME_DOMAIN = 'example.com';
const NETWORK_PASSPHRASE = Networks.TESTNET;

function makeApp() {
  const serverKeypair = Keypair.random();
  const { app } = createApp({
    serverKeypair,
    homeDomain: HOME_DOMAIN,
    webAuthDomain: HOME_DOMAIN,
    networkPassphrase: NETWORK_PASSPHRASE,
  });
  return { app, serverKeypair };
}

describe('SEP-10 express-app example', () => {
  describe('GET /auth', () => {
    it('returns 400 when the account query parameter is missing', async () => {
      const { app } = makeApp();

      const res = await request(app).get('/auth');

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/account/i);
    });

    it('returns 400 when the account query parameter is not a valid Stellar key', async () => {
      const { app } = makeApp();

      const res = await request(app).get('/auth').query({ account: 'not-a-key' });

      expect(res.status).toBe(400);
    });

    it('returns 400 when home_domain is not one of the configured domains', async () => {
      const { app } = makeApp();

      const res = await request(app)
        .get('/challenge')
        .query({ address: Keypair.random().publicKey(), home_domain: 'evil.example.net' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/home_domain/);
    });

    it('accepts a configured home_domain and falls back to the first one when omitted', async () => {
      const serverKeypair = Keypair.random();
      const { app } = createApp({
        serverKeypair,
        homeDomains: [HOME_DOMAIN, 'other.example.org'],
        networkPassphrase: NETWORK_PASSPHRASE,
      });
      const address = Keypair.random().publicKey();

      const explicit = await request(app)
        .get('/challenge')
        .query({ address, home_domain: 'other.example.org' });
      const fallback = await request(app).get('/challenge').query({ address });

      expect(explicit.status).toBe(200);
      expect(fallback.status).toBe(200);
    });

    it('returns a challenge transaction for a valid client address', async () => {
      const { app } = makeApp();
      const client = Keypair.random();

      const res = await request(app).get('/auth').query({ account: client.publicKey() });

      expect(res.status).toBe(200);
      expect(typeof res.body.transaction).toBe('string');
      expect(res.body.network_passphrase).toBe(NETWORK_PASSPHRASE);

      // The returned XDR must parse as a transaction on the advertised network.
      expect(
        () => new Transaction(res.body.transaction, res.body.network_passphrase),
      ).not.toThrow();
    });
  });

  describe('GET /protected', () => {
    it('returns 401 when no Authorization header is provided', async () => {
      const { app } = makeApp();

      const res = await request(app).get('/protected');

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('unauthorized');
    });

    it('returns 401 when the bearer token is not a valid signed challenge', async () => {
      const { app } = makeApp();

      const res = await request(app)
        .get('/protected')
        .set('Authorization', 'Bearer not-a-real-signed-xdr');

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('unauthorized');
    });

    it('completes the full challenge/verify roundtrip and returns the authenticated address', async () => {
      const { app } = makeApp();
      const client = Keypair.random();

      // 1. Request a challenge.
      const challengeRes = await request(app)
        .get('/auth')
        .query({ account: client.publicKey() });
      expect(challengeRes.status).toBe(200);

      // 2. Sign it with the client's key, exactly as a wallet would.
      const tx = new Transaction(
        challengeRes.body.transaction,
        challengeRes.body.network_passphrase,
      );
      tx.sign(client);
      const signedXDR = tx.toXDR();

      // 3. Call the protected route with the signed XDR as a bearer token.
      const protectedRes = await request(app)
        .get('/protected')
        .set('Authorization', `Bearer ${signedXDR}`);

      expect(protectedRes.status).toBe(200);
      expect(protectedRes.body.address).toBe(client.publicKey());
    });

    it('rejects a challenge signed by a different key than it was issued for', async () => {
      const { app } = makeApp();
      const client = Keypair.random();
      const attacker = Keypair.random();

      const challengeRes = await request(app)
        .get('/auth')
        .query({ account: client.publicKey() });

      const tx = new Transaction(
        challengeRes.body.transaction,
        challengeRes.body.network_passphrase,
      );
      tx.sign(attacker);

      const protectedRes = await request(app)
        .get('/protected')
        .set('Authorization', `Bearer ${tx.toXDR()}`);

      expect(protectedRes.status).toBe(401);
    });
  });
});
