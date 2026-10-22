/**
 * Security-focused boundary-case tests for sep10-auth challenge/verify.
 *
 * Covers three attack vectors that are explicitly out of scope for the
 * general verify.test.ts happy-path and expiry tests:
 *
 *  1. Signature substitution — swap in a different valid signer's signature.
 *  2. Domain confusion   — challenge built for one domain, verified against another.
 *  3. Challenge tampering — mutate a byte of a validly-signed XDR.
 */

///<reference types="jest" />
import { Keypair, Networks, Transaction } from '@stellar/stellar-sdk';
import { generateChallenge } from '../src/challenge';
import { verifyChallenge } from '../src/verify';

const NETWORK = Networks.TESTNET;
const HOME_DOMAIN = 'auth.example.com';
const OTHER_DOMAIN = 'evil.example.com';

/** Signs the challenge transaction as `signerKeypair` and returns the signed XDR. */
function signAs(transactionXDR: string, signerKeypair: Keypair): string {
  const tx = new Transaction(transactionXDR, NETWORK);
  tx.sign(signerKeypair);
  return tx.toXDR();
}

/**
 * Builds a standard valid signed challenge for `clientKeypair` issued by
 * `serverKeypair` for `homeDomain`.
 */
function buildSignedChallenge(
  serverKeypair: Keypair,
  clientKeypair: Keypair,
  homeDomain = HOME_DOMAIN,
): string {
  const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair, {
    homeDomain,
    webAuthDomain: homeDomain,
    networkPassphrase: NETWORK,
  });
  return signAs(challenge.transactionXDR, clientKeypair);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Signature substitution
// ─────────────────────────────────────────────────────────────────────────────

describe('Security: signature substitution', () => {
  it('rejects a challenge signed by a different (valid) keypair instead of the client', async () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();
    const attackerKeypair = Keypair.random(); // attacker has a valid Stellar keypair

    const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair, {
      homeDomain: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
      networkPassphrase: NETWORK,
    });

    // Attacker signs the challenge with their own key instead of the client's.
    const attackerSignedXDR = signAs(challenge.transactionXDR, attackerKeypair);

    const result = await verifyChallenge(attackerSignedXDR, {
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase: NETWORK,
      homeDomains: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
    });

    expect(result.valid).toBe(false);
    expect(result.address).toBe('');
    expect(result.error).toBeDefined();
  });

  it('rejects when the challenge is double-signed by both client and attacker (only client sig expected)', async () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();
    const attackerKeypair = Keypair.random();

    const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair, {
      homeDomain: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
      networkPassphrase: NETWORK,
    });

    // Both client and attacker append their signatures.
    const tx = new Transaction(challenge.transactionXDR, NETWORK);
    tx.sign(clientKeypair, attackerKeypair);
    const doubleSignedXDR = tx.toXDR();

    // The SEP-10 spec requires the signer set to match exactly the client
    // account — extra unrecognised signers should not be silently accepted.
    const result = await verifyChallenge(doubleSignedXDR, {
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase: NETWORK,
      homeDomains: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
    });

    // WebAuth.verifyChallengeTxSigners rejects transactions signed by
    // accounts that are not in the expected signer set.
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('rejects when the attacker replaces the client signature with their own (no client sig)', async () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();
    const attackerKeypair = Keypair.random();

    const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair, {
      homeDomain: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
      networkPassphrase: NETWORK,
    });

    // Only the attacker signs — client never touches it.
    const attackerOnlyXDR = signAs(challenge.transactionXDR, attackerKeypair);

    const result = await verifyChallenge(attackerOnlyXDR, {
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase: NETWORK,
      homeDomains: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
    });

    expect(result.valid).toBe(false);
    expect(result.address).toBe('');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Domain confusion
// ─────────────────────────────────────────────────────────────────────────────

describe('Security: domain confusion', () => {
  it('rejects a challenge built for domain A when verified against domain B', async () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();

    // Challenge issued for HOME_DOMAIN …
    const signedXDR = buildSignedChallenge(serverKeypair, clientKeypair, HOME_DOMAIN);

    // … but the verifier claims to be OTHER_DOMAIN.
    const result = await verifyChallenge(signedXDR, {
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase: NETWORK,
      homeDomains: OTHER_DOMAIN,
      webAuthDomain: OTHER_DOMAIN,
    });

    expect(result.valid).toBe(false);
    expect(result.address).toBe('');
    expect(result.error).toBeDefined();
  });

  it('rejects when homeDomain matches but webAuthDomain is wrong', async () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();

    const signedXDR = buildSignedChallenge(serverKeypair, clientKeypair, HOME_DOMAIN);

    const result = await verifyChallenge(signedXDR, {
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase: NETWORK,
      homeDomains: HOME_DOMAIN,
      webAuthDomain: OTHER_DOMAIN, // wrong webAuthDomain
    });

    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('rejects when the challenge uses a different server keypair than expected', async () => {
    const serverKeypairA = Keypair.random(); // actual issuer
    const serverKeypairB = Keypair.random(); // what the verifier trusts
    const clientKeypair = Keypair.random();

    const signedXDR = buildSignedChallenge(serverKeypairA, clientKeypair);

    // Verifier trusts serverKeypairB but challenge was signed by serverKeypairA.
    const result = await verifyChallenge(signedXDR, {
      serverAccountId: serverKeypairB.publicKey(), // wrong server
      networkPassphrase: NETWORK,
      homeDomains: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('accepts a correctly-paired challenge when multiple home domains are allowed', async () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();

    const signedXDR = buildSignedChallenge(serverKeypair, clientKeypair, HOME_DOMAIN);

    const result = await verifyChallenge(signedXDR, {
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase: NETWORK,
      homeDomains: [HOME_DOMAIN, OTHER_DOMAIN], // both allowed
      webAuthDomain: HOME_DOMAIN,
    });

    expect(result.valid).toBe(true);
    expect(result.address).toBe(clientKeypair.publicKey());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Challenge tampering
// ─────────────────────────────────────────────────────────────────────────────

describe('Security: challenge tampering', () => {
  /**
   * Flips a single bit in the middle of a base64-decoded XDR buffer, then
   * re-encodes it. Returns the tampered XDR string, or the original string if
   * the chosen byte happens to produce valid base64 again after the mutation
   * (this is avoided by targeting a non-padding position).
   */
  function tamperXDR(xdrBase64: string): string {
    const buf = Buffer.from(xdrBase64, 'base64');
    // Target a byte roughly in the middle of the payload — far from the header
    // and signatures so we corrupt the operation body rather than checksum.
    const targetIndex = Math.floor(buf.length / 2);
    buf[targetIndex] = buf[targetIndex] ^ 0xff; // flip all bits in that byte
    return buf.toString('base64');
  }

  it('rejects a challenge whose XDR has been mutated after signing', async () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();

    const signedXDR = buildSignedChallenge(serverKeypair, clientKeypair);
    const tamperedXDR = tamperXDR(signedXDR);

    // A tampered XDR will either fail to parse, fail signature verification,
    // or fail the SEP-10 structural checks — all of which should return invalid.
    const result = await verifyChallenge(tamperedXDR, {
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase: NETWORK,
      homeDomains: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('rejects a challenge whose operation memo has been altered after signing', async () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();

    const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair, {
      homeDomain: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
      networkPassphrase: NETWORK,
    });

    // Sign the original challenge first.
    const tx = new Transaction(challenge.transactionXDR, NETWORK);
    tx.sign(clientKeypair);

    // Now deserialise via XDR envelope, mutate the first operation's body
    // (flip bits in the data name field) and re-encode.  This simulates an
    // attacker replacing the nonce after the client signed.
    const envelope = tx.toEnvelope();
    const txXdr = envelope.toXDR();
    const midpoint = Math.floor(txXdr.length / 3);
    txXdr[midpoint] = txXdr[midpoint] ^ 0x01;
    const tamperedBase64 = txXdr.toString('base64');

    const result = await verifyChallenge(tamperedBase64, {
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase: NETWORK,
      homeDomains: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('accepts the original XDR unchanged after signing (control case)', async () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();

    const signedXDR = buildSignedChallenge(serverKeypair, clientKeypair);

    const result = await verifyChallenge(signedXDR, {
      serverAccountId: serverKeypair.publicKey(),
      networkPassphrase: NETWORK,
      homeDomains: HOME_DOMAIN,
      webAuthDomain: HOME_DOMAIN,
    });

    expect(result.valid).toBe(true);
    expect(result.address).toBe(clientKeypair.publicKey());
  });
});
