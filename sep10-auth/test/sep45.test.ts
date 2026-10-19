///<reference types="jest" />
import { Keypair, Networks, StrKey, xdr } from '@stellar/stellar-sdk';
import {
  generateContractChallenge,
  verifyContractChallenge,
  WEB_AUTH_FUNCTION_NAME,
} from '../src/sep45';

const homeDomain = 'anchor.example.com';
const webAuthContractId = StrKey.encodeContract(Buffer.alloc(32, 7));
const clientContractId = StrKey.encodeContract(Buffer.alloc(32, 9));
const validUntilLedger = 1000;

/** Marks the client entry as signed the way a contract account would (opaque bytes). */
function signAsContractClient(entriesXDR: string[]): string[] {
  return entriesXDR.map((b64) => {
    const entry = xdr.SorobanAuthorizationEntry.fromXDR(b64, 'base64');
    const creds = entry.credentials().address();
    if (creds.address().switch().name === 'scAddressTypeContract') {
      creds.signature(xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.from('contract-signature'))]));
    }
    return entry.toXDR('base64');
  });
}

async function setup() {
  const serverKeypair = Keypair.random();
  const challenge = await generateContractChallenge(clientContractId, serverKeypair, {
    webAuthContractId,
    validUntilLedger,
    homeDomain,
  });
  const verifyOptions = {
    webAuthContractId,
    serverAccountId: serverKeypair.publicKey(),
    homeDomains: homeDomain,
    webAuthDomain: homeDomain,
    networkPassphrase: Networks.TESTNET,
    currentLedger: 900,
    verifyClientAuthorization: jest.fn().mockResolvedValue(true),
  };
  return { serverKeypair, challenge, verifyOptions };
}

describe('generateContractChallenge', () => {
  it('builds a server-signed entry and an unsigned client entry for web_auth_verify', async () => {
    const { challenge, serverKeypair } = await setup();

    expect(challenge.authorizationEntries).toHaveLength(2);
    expect(challenge.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(challenge.networkPassphrase).toBe(Networks.TESTNET);

    const [server, client] = challenge.authorizationEntries.map((b64) =>
      xdr.SorobanAuthorizationEntry.fromXDR(b64, 'base64'),
    );
    const call = server.rootInvocation().function().contractFn();
    expect(call.functionName().toString()).toBe(WEB_AUTH_FUNCTION_NAME);

    const args = call.args()[0].map()!;
    const asObject = Object.fromEntries(
      args.map((e) => [e.key().str().toString(), e.val().str().toString()]),
    );
    expect(asObject).toEqual({
      account: clientContractId,
      home_domain: homeDomain,
      nonce: challenge.nonce,
      web_auth_domain: homeDomain,
      web_auth_domain_account: serverKeypair.publicKey(),
    });

    expect(server.credentials().address().signature().vec()).toHaveLength(1);
    expect(client.credentials().address().signature().vec()).toHaveLength(0);
  });

  it('rejects non-contract client accounts and bad inputs', async () => {
    const serverKeypair = Keypair.random();
    const base = { webAuthContractId, validUntilLedger, homeDomain };

    await expect(
      generateContractChallenge(Keypair.random().publicKey(), serverKeypair, base),
    ).rejects.toThrow(/contract address/);
    await expect(
      generateContractChallenge(clientContractId, serverKeypair, { ...base, webAuthContractId: 'nope' }),
    ).rejects.toThrow(/webAuthContractId/);
    await expect(
      generateContractChallenge(clientContractId, serverKeypair, { ...base, validUntilLedger: 0 }),
    ).rejects.toThrow(/validUntilLedger/);
    await expect(
      generateContractChallenge(clientContractId, serverKeypair, { ...base, homeDomain: 'https://x.com' }),
    ).rejects.toThrow(/bare domain/);
    await expect(
      generateContractChallenge(clientContractId, Keypair.fromPublicKey(serverKeypair.publicKey()), base),
    ).rejects.toThrow(/cannot sign/);
  });
});

describe('verifyContractChallenge', () => {
  it('accepts a round-tripped challenge and returns the contract account and nonce', async () => {
    const { challenge, verifyOptions } = await setup();
    const signed = signAsContractClient(challenge.authorizationEntries);

    const result = await verifyContractChallenge(signed, verifyOptions);

    expect(result).toEqual({
      valid: true,
      address: clientContractId,
      nonce: challenge.nonce,
      homeDomain,
    });
    expect(verifyOptions.verifyClientAuthorization).toHaveBeenCalledTimes(1);
  });

  it('rejects a challenge whose client entry is unsigned', async () => {
    const { challenge, verifyOptions } = await setup();
    const result = await verifyContractChallenge(challenge.authorizationEntries, verifyOptions);
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe('WRONG_SIGNER');
    expect(verifyOptions.verifyClientAuthorization).not.toHaveBeenCalled();
  });

  it('rejects when the client authorization callback says the signature is invalid', async () => {
    const { challenge, verifyOptions } = await setup();
    verifyOptions.verifyClientAuthorization.mockResolvedValue(false);
    const result = await verifyContractChallenge(
      signAsContractClient(challenge.authorizationEntries),
      verifyOptions,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe('WRONG_SIGNER');
  });

  it('rejects an expired challenge', async () => {
    const { challenge, verifyOptions } = await setup();
    const result = await verifyContractChallenge(signAsContractClient(challenge.authorizationEntries), {
      ...verifyOptions,
      currentLedger: validUntilLedger + 1,
    });
    expect(result.errorCode).toBe('CHALLENGE_EXPIRED');
  });

  it('rejects the wrong home domain and web auth domain', async () => {
    const { challenge, verifyOptions } = await setup();
    const signed = signAsContractClient(challenge.authorizationEntries);

    expect((await verifyContractChallenge(signed, { ...verifyOptions, homeDomains: 'other.example.com' })).errorCode).toBe('WRONG_DOMAIN');
    expect((await verifyContractChallenge(signed, { ...verifyOptions, webAuthDomain: ['other.example.com'] })).errorCode).toBe('WRONG_DOMAIN');
  });

  it('rejects a different web auth contract', async () => {
    const { challenge, verifyOptions } = await setup();
    const result = await verifyContractChallenge(signAsContractClient(challenge.authorizationEntries), {
      ...verifyOptions,
      webAuthContractId: StrKey.encodeContract(Buffer.alloc(32, 1)),
    });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe('INVALID_CHALLENGE');
  });

  it('rejects a challenge issued by a different server key', async () => {
    const { challenge, verifyOptions } = await setup();
    const result = await verifyContractChallenge(signAsContractClient(challenge.authorizationEntries), {
      ...verifyOptions,
      serverAccountId: Keypair.random().publicKey(),
    });
    expect(result.valid).toBe(false);
  });

  it('rejects a tampered server signature', async () => {
    const { challenge, verifyOptions } = await setup();
    const signed = signAsContractClient(challenge.authorizationEntries);

    const server = xdr.SorobanAuthorizationEntry.fromXDR(signed[0], 'base64');
    const sigMap = server.credentials().address().signature().vec()![0].map()!;
    const sigEntry = sigMap.find((e) => e.key().sym().toString() === 'signature')!;
    const bytes = Buffer.from(sigEntry.val().bytes());
    bytes[0] ^= 0xff;
    sigEntry.val(xdr.ScVal.scvBytes(bytes));

    const result = await verifyContractChallenge([server.toXDR('base64'), signed[1]], verifyOptions);
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe('WRONG_SIGNER');
  });

  it('rejects malformed input without throwing', async () => {
    const { verifyOptions } = await setup();
    expect((await verifyContractChallenge(['not-xdr', 'not-xdr'], verifyOptions)).errorCode).toBe('INVALID_CHALLENGE');
    expect((await verifyContractChallenge([], verifyOptions)).errorCode).toBe('INVALID_CHALLENGE');
    expect((await verifyContractChallenge([], { ...verifyOptions, serverAccountId: 'x' })).errorCode).toBe('INVALID_SERVER_ACCOUNT_ID');
    expect((await verifyContractChallenge([], { ...verifyOptions, webAuthContractId: 'x' })).errorCode).toBe('INVALID_OPTIONS');
    expect((await verifyContractChallenge([], { ...verifyOptions, homeDomains: 'http://x' })).errorCode).toBe('INVALID_OPTIONS');
  });
});
