/// <reference types="jest" />

import Fastify from 'fastify';
import { Keypair, Networks, Transaction } from '@stellar/stellar-sdk';
import { generateChallenge } from '../src/challenge';
import { authenticateRequest } from '../src/middleware';
import { sep10Plugin } from '../src/fastify';
import type { RevocationStore } from '../src/revocation';

const HOME_DOMAIN = 'example.com';
const serverKeypair = Keypair.random();
const pluginOptions = {
  serverAccountId: serverKeypair.publicKey(),
  networkPassphrase: Networks.TESTNET,
  homeDomains: HOME_DOMAIN,
  webAuthDomain: HOME_DOMAIN,
};

function signedChallenge(client: Keypair): string {
  const challenge = generateChallenge(client.publicKey(), serverKeypair, {
    homeDomain: HOME_DOMAIN,
    webAuthDomain: HOME_DOMAIN,
    networkPassphrase: Networks.TESTNET,
  });
  const tx = new Transaction(challenge.transactionXDR, challenge.networkPassphrase);
  tx.sign(client);
  return tx.toXDR();
}

async function buildApp(options: Record<string, unknown> = {}) {
  const app = Fastify();
  await app.register(sep10Plugin, { ...pluginOptions, ...options } as any);
  app.get('/status', async (request) => ({ address: request.stellarAddress }));
  return app;
}

describe('sep10Plugin (Fastify)', () => {
  it('decorates request.stellarAddress for a valid signed challenge', async () => {
    const app = await buildApp();
    const client = Keypair.random();

    const res = await app.inject({
      method: 'GET',
      url: '/status',
      headers: { authorization: `Bearer ${signedChallenge(client)}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ address: client.publicKey() });
  });

  it('returns 401 with WWW-Authenticate invalid_request when the header is missing', async () => {
    const app = await buildApp();

    const res = await app.inject({ method: 'GET', url: '/status' });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({
      error: 'unauthorized',
      code: 'missing_token',
      details: { reason: 'missing bearer token' },
    });
    expect(res.headers['www-authenticate']).toBe(
      'Bearer realm="example.com", error="invalid_request"',
    );
  });

  it('returns 401 with WWW-Authenticate invalid_token for an invalid token', async () => {
    const app = await buildApp();

    const res = await app.inject({
      method: 'GET',
      url: '/status',
      headers: { authorization: 'Bearer not-a-real-xdr' },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('unauthorized');
    expect(res.headers['www-authenticate']).toBe(
      'Bearer realm="example.com", error="invalid_token"',
    );
  });

  it('rejects a challenge signed by a different key', async () => {
    const app = await buildApp();
    const client = Keypair.random();
    const challenge = generateChallenge(client.publicKey(), serverKeypair, {
      homeDomain: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
      networkPassphrase: Networks.TESTNET,
    });
    const tx = new Transaction(challenge.transactionXDR, challenge.networkPassphrase);
    tx.sign(Keypair.random());

    const res = await app.inject({
      method: 'GET',
      url: '/status',
      headers: { authorization: `Bearer ${tx.toXDR()}` },
    });

    expect(res.statusCode).toBe(401);
  });

  it('rejects revoked addresses', async () => {
    const store: RevocationStore = {
      isRevoked: jest.fn().mockResolvedValue(true),
      revoke: jest.fn(),
      unrevoke: jest.fn(),
    };
    const app = await buildApp({ revocationStore: store });

    const res = await app.inject({
      method: 'GET',
      url: '/status',
      headers: { authorization: `Bearer ${signedChallenge(Keypair.random())}` },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe('token_revoked');
    expect(res.json().details.reason).toBe('address revoked');
  });

  it('responds 500 when the revocation store fails', async () => {
    const store: RevocationStore = {
      isRevoked: jest.fn().mockRejectedValue(new Error('db down')),
      revoke: jest.fn(),
      unrevoke: jest.fn(),
    };
    const app = await buildApp({ revocationStore: store });

    const res = await app.inject({
      method: 'GET',
      url: '/status',
      headers: { authorization: `Bearer ${signedChallenge(Keypair.random())}` },
    });

    expect(res.statusCode).toBe(500);
  });

  it('only guards routes using sep10Authenticate when global is false', async () => {
    const app = Fastify();
    await app.register(sep10Plugin, { ...pluginOptions, global: false });
    app.get('/public', async () => ({ ok: true }));
    app.get('/private', { preHandler: app.sep10Authenticate }, async (request) => ({
      address: request.stellarAddress,
    }));

    expect((await app.inject({ method: 'GET', url: '/public' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/private' })).statusCode).toBe(401);
  });

  it('throws at registration for an invalid serverAccountId', async () => {
    const app = Fastify();
    await expect(
      app.register(sep10Plugin, { ...pluginOptions, serverAccountId: 'nope' }).ready(),
    ).rejects.toThrow(/serverAccountId/);
  });
});

describe('authenticateRequest (framework-agnostic core)', () => {
  it('returns the address for a valid token', async () => {
    const client = Keypair.random();
    const result = await authenticateRequest(
      { authorization: `Bearer ${signedChallenge(client)}` },
      pluginOptions,
    );
    expect(result).toEqual(expect.objectContaining({ ok: true, address: client.publicKey() }));
  });

  it('reads a capitalised Authorization header', async () => {
    const client = Keypair.random();
    const result = await authenticateRequest(
      { Authorization: `Bearer ${signedChallenge(client)}` },
      pluginOptions,
    );
    expect(result.ok).toBe(true);
  });

  it('reports invalid_request for a missing header', async () => {
    const result = await authenticateRequest({}, pluginOptions);
    expect(result).toEqual(
      expect.objectContaining({ ok: false, error: 'invalid_request', reason: 'missing bearer token' }),
    );
  });
});
