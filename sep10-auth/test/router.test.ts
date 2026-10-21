/// <reference types="jest" />

import express from 'express';
import request from 'supertest';
import { createHmac } from 'crypto';
import { Keypair, Networks, Transaction } from '@stellar/stellar-sdk';
import { createSep10Router } from '../src/router';
import { issueJwt } from '../src/jwt';

const HOME_DOMAIN = 'example.com';

function makeApp(overrides: Partial<Parameters<typeof createSep10Router>[0]> = {}) {
  const serverKeypair = Keypair.random();
  const app = express();
  app.use(
    createSep10Router({
      serverKeypair,
      homeDomain: HOME_DOMAIN,
      networkPassphrase: Networks.TESTNET,
      jwtSecret: 'test-secret',
      ...overrides,
    }),
  );
  return { app, serverKeypair };
}

function decodeJwt(token: string): { header: any; claims: any; signature: string } {
  const [h, c, signature] = token.split('.');
  return {
    header: JSON.parse(Buffer.from(h, 'base64url').toString()),
    claims: JSON.parse(Buffer.from(c, 'base64url').toString()),
    signature,
  };
}

async function signedChallenge(app: express.Express, client: Keypair): Promise<string> {
  const res = await request(app).get('/auth').query({ account: client.publicKey() });
  const tx = new Transaction(res.body.transaction, res.body.network_passphrase);
  tx.sign(client);
  return tx.toXDR();
}

describe('createSep10Router', () => {
  describe('construction', () => {
    it('throws when neither jwtSecret nor issueToken is provided', () => {
      expect(() =>
        createSep10Router({ serverKeypair: Keypair.random(), homeDomain: HOME_DOMAIN }),
      ).toThrow(/jwtSecret or issueToken/);
    });

    it('throws when the server keypair cannot sign', () => {
      expect(() =>
        createSep10Router({
          serverKeypair: Keypair.fromPublicKey(Keypair.random().publicKey()),
          homeDomain: HOME_DOMAIN,
          jwtSecret: 's',
        }),
      ).toThrow(/sign/);
    });

    it('throws for a non-bare home domain', () => {
      expect(() =>
        createSep10Router({
          serverKeypair: Keypair.random(),
          homeDomain: 'https://example.com',
          jwtSecret: 's',
        }),
      ).toThrow(/bare domain/);
    });
  });

  describe('GET /auth', () => {
    it('returns { transaction, network_passphrase } for a valid account', async () => {
      const { app } = makeApp();
      const client = Keypair.random();

      const res = await request(app).get('/auth').query({ account: client.publicKey() });

      expect(res.status).toBe(200);
      expect(res.body.network_passphrase).toBe(Networks.TESTNET);
      expect(
        () => new Transaction(res.body.transaction, res.body.network_passphrase),
      ).not.toThrow();
    });

    it('returns 400 when account is missing', async () => {
      const { app } = makeApp();
      const res = await request(app).get('/auth');
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/account/);
    });

    it('returns 400 when account is not a valid Stellar key', async () => {
      const { app } = makeApp();
      const res = await request(app).get('/auth').query({ account: 'nope' });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/account/);
    });

    it('returns 400 for an unknown home_domain', async () => {
      const { app } = makeApp();
      const res = await request(app)
        .get('/auth')
        .query({ account: Keypair.random().publicKey(), home_domain: 'evil.com' });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/home_domain/);
    });

    it('accepts any configured home_domain', async () => {
      const { app } = makeApp({ homeDomain: [HOME_DOMAIN, 'other.example.com'] });
      const res = await request(app)
        .get('/auth')
        .query({ account: Keypair.random().publicKey(), home_domain: 'other.example.com' });
      expect(res.status).toBe(200);
    });

    it('returns 400 for an invalid memo', async () => {
      const { app } = makeApp();
      const res = await request(app)
        .get('/auth')
        .query({ account: Keypair.random().publicKey(), memo: 'abc' });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/memo/);
    });

    it('returns 400 for client_domain when no resolver is configured', async () => {
      const { app } = makeApp();
      const res = await request(app)
        .get('/auth')
        .query({ account: Keypair.random().publicKey(), client_domain: 'wallet.example.org' });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/client_domain/);
    });

    it('returns 400 when the client_domain signing key cannot be resolved', async () => {
      const { app } = makeApp({
        resolveClientSigningKey: async () => {
          throw new Error('no toml');
        },
      });
      const res = await request(app)
        .get('/auth')
        .query({ account: Keypair.random().publicKey(), client_domain: 'wallet.example.org' });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/client_domain/);
    });

    it('builds a challenge with the resolved client_domain signing key', async () => {
      const clientSigner = Keypair.random();
      const resolve = jest.fn().mockResolvedValue(clientSigner.publicKey());
      const { app } = makeApp({ resolveClientSigningKey: resolve });

      const res = await request(app)
        .get('/auth')
        .query({ account: Keypair.random().publicKey(), client_domain: 'wallet.example.org' });

      expect(res.status).toBe(200);
      expect(resolve).toHaveBeenCalledWith('wallet.example.org');
    });
  });

  describe('POST /auth', () => {
    it('exchanges a signed challenge for a JWT (JSON body)', async () => {
      const { app } = makeApp();
      const client = Keypair.random();
      const signed = await signedChallenge(app, client);

      const res = await request(app).post('/auth').send({ transaction: signed });

      expect(res.status).toBe(200);
      const { header, claims, signature } = decodeJwt(res.body.token);
      expect(header).toEqual({ alg: 'HS256', typ: 'JWT' });
      expect(claims.sub).toBe(client.publicKey());
      expect(claims.iss).toBe(`https://${HOME_DOMAIN}`);
      expect(claims.exp - claims.iat).toBe(86400);
      const [h, c] = res.body.token.split('.');
      expect(signature).toBe(
        createHmac('sha256', 'test-secret').update(`${h}.${c}`).digest().toString('base64url'),
      );
    });

    it('accepts a form-encoded body', async () => {
      const { app } = makeApp();
      const signed = await signedChallenge(app, Keypair.random());

      const res = await request(app).post('/auth').type('form').send({ transaction: signed });

      expect(res.status).toBe(200);
      expect(typeof res.body.token).toBe('string');
    });

    it('uses a custom issueToken', async () => {
      const issueToken = jest.fn().mockResolvedValue('custom-token');
      const { app } = makeApp({ jwtSecret: undefined, issueToken });
      const client = Keypair.random();
      const signed = await signedChallenge(app, client);

      const res = await request(app).post('/auth').send({ transaction: signed });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ token: 'custom-token' });
      expect(issueToken).toHaveBeenCalledWith(
        client.publicKey(),
        expect.objectContaining({ transaction: signed }),
      );
    });

    it('returns 400 when transaction is missing', async () => {
      const { app } = makeApp();
      const res = await request(app).post('/auth').send({});
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/transaction/);
    });

    it('returns 400 when transaction is too large', async () => {
      const { app } = makeApp({ maxTransactionLength: 10 });
      const res = await request(app).post('/auth').send({ transaction: 'a'.repeat(11) });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/too large/);
    });

    it('returns 400 for a garbage transaction', async () => {
      const { app } = makeApp();
      const res = await request(app).post('/auth').send({ transaction: 'not-xdr' });
      expect(res.status).toBe(400);
      expect(typeof res.body.error).toBe('string');
    });

    it('returns 400 for a challenge the client did not sign', async () => {
      const { app } = makeApp();
      const client = Keypair.random();
      const res = await request(app).get('/auth').query({ account: client.publicKey() });

      const unsigned = await request(app).post('/auth').send({ transaction: res.body.transaction });

      expect(unsigned.status).toBe(400);
      expect(typeof unsigned.body.error).toBe('string');
    });

    it('returns 400 for a challenge signed by a different key', async () => {
      const { app } = makeApp();
      const client = Keypair.random();
      const res = await request(app).get('/auth').query({ account: client.publicKey() });
      const tx = new Transaction(res.body.transaction, res.body.network_passphrase);
      tx.sign(Keypair.random());

      const out = await request(app).post('/auth').send({ transaction: tx.toXDR() });

      expect(out.status).toBe(400);
    });

    it('returns 400 for a challenge issued by a different server', async () => {
      const { app } = makeApp();
      const other = makeApp();
      const client = Keypair.random();
      const signed = await signedChallenge(other.app, client);

      const res = await request(app).post('/auth').send({ transaction: signed });

      expect(res.status).toBe(400);
    });

    it('forwards an issueToken failure to the error handler', async () => {
      const { app } = makeApp({
        jwtSecret: undefined,
        issueToken: async () => {
          throw new Error('boom');
        },
      });
      const signed = await signedChallenge(app, Keypair.random());

      const res = await request(app).post('/auth').send({ transaction: signed });

      expect(res.status).toBe(500);
    });
  });

  describe('rate limiting', () => {
    it('throttles requests with 429 and RateLimit-* headers', async () => {
      const { app } = makeApp({ rateLimit: { maxRequests: 2, windowMs: 60_000 } });
      const account = Keypair.random().publicKey();

      const first = await request(app).get('/auth').query({ account });
      expect(first.headers['ratelimit-limit']).toBe('2');
      expect(first.headers['ratelimit-remaining']).toBe('1');
      await request(app).get('/auth').query({ account });
      const throttled = await request(app).get('/auth').query({ account });

      expect(throttled.status).toBe(429);
      expect(throttled.body.error).toBe('Too many requests');
      expect(throttled.body.code).toBe('rate_limit_exceeded');
    });

    it('can be disabled', async () => {
      const { app } = makeApp({ rateLimit: false });
      const res = await request(app).get('/auth').query({ account: Keypair.random().publicKey() });
      expect(res.status).toBe(200);
      expect(res.headers['ratelimit-limit']).toBeUndefined();
    });
  });
});

describe('issueJwt', () => {
  it('includes client_domain and honours expiresInSeconds and now', () => {
    const token = issueJwt({
      secret: 's',
      issuer: 'https://example.com',
      subject: 'GABC',
      expiresInSeconds: 60,
      now: 1_000_000,
      clientDomain: 'wallet.example.org',
    });
    const { claims } = decodeJwt(token);
    expect(claims).toEqual(
      expect.objectContaining({
        iss: 'https://example.com',
        sub: 'GABC',
        iat: 1000,
        exp: 1060,
        client_domain: 'wallet.example.org',
      }),
    );
  });
});
