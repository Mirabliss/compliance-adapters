/// <reference types="jest" />
/**
 * Property-based / fuzz tests for verifyChallenge.
 *
 * Goal: confirm that verifyChallenge NEVER throws an uncaught exception and
 * ALWAYS returns a structurally valid VerifyResult regardless of what
 * arbitrary bytes/strings are supplied as the signedTransactionXDR argument.
 *
 * `verifyChallenge` parses untrusted client input (a signed XDR string), so
 * it must be hardened against every kind of malformed input without leaking
 * an unhandled exception to callers.
 */
import * as fc from 'fast-check';
import { Keypair, Networks, Transaction } from '@stellar/stellar-sdk';
import { generateChallenge } from '../src/challenge';
import { verifyChallenge, VerifyChallengeOptions } from '../src/verify';

// ---------------------------------------------------------------------------
// Fixed options shared across all property tests.
// The server keypair is kept stable within a test run; we're fuzzing the
// *input XDR*, not the options.
// ---------------------------------------------------------------------------
const serverKeypair = Keypair.random();

const verifyOpts: VerifyChallengeOptions = {
  serverAccountId: serverKeypair.publicKey(),
  networkPassphrase: Networks.TESTNET,
  homeDomains: 'localhost:3000',
  webAuthDomain: 'localhost:3000',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Assert that a value has the exact shape of VerifyResult. */
function assertValidResult(result: unknown): void {
  expect(result).not.toBeNull();
  expect(typeof result).toBe('object');
  const r = result as Record<string, unknown>;
  expect(typeof r.valid).toBe('boolean');
  expect(typeof r.address).toBe('string');
  // error must be either absent/undefined or a non-empty string
  if (r.error !== undefined) {
    expect(typeof r.error).toBe('string');
    expect((r.error as string).length).toBeGreaterThan(0);
  }
}

/** Build a valid signed XDR string so we have a real base to corrupt. */
function buildValidSignedXDR(clientKeypair: Keypair): string {
  const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair, {
    homeDomain: 'localhost:3000',
    webAuthDomain: 'localhost:3000',
    networkPassphrase: Networks.TESTNET,
  });
  const tx = new Transaction(challenge.transactionXDR, Networks.TESTNET);
  tx.sign(clientKeypair);
  return tx.toXDR();
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

describe('verifyChallenge – property-based / fuzz tests', () => {
  /**
   * P1: Arbitrary Unicode strings
   * Every imaginable string input must result in a clean VerifyResult, never
   * an uncaught throw. This catches unguarded JSON.parse, atob, or XDR
   * parsing that might surface internal SDK errors.
   */
  it('P1: never throws for arbitrary unicode strings', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string(), async (input) => {
        const result = await verifyChallenge(input, verifyOpts);
        assertValidResult(result);
        // Arbitrary garbage strings must always fail verification cleanly
        expect(result.valid).toBe(false);
        expect(result.address).toBe('');
      }),
      { numRuns: 500, seed: 0xcafe },
    );
  });

  /**
   * P2: Malformed-but-valid base64 strings
   * Inputs that are syntactically valid base64 but decode to random bytes.
   * The SDK's XDR parser must fail gracefully and not throw.
   */
  it('P2: never throws for malformed-but-valid base64 input', async () => {
    // fc.base64String() generates strings safe for standard base64 encoding
    const base64Arb = fc
      .uint8Array({ minLength: 1, maxLength: 1024 })
      .map((bytes) => Buffer.from(bytes).toString('base64'));

    await fc.assert(
      fc.asyncProperty(base64Arb, async (input) => {
        const result = await verifyChallenge(input, verifyOpts);
        assertValidResult(result);
        expect(result.valid).toBe(false);
        expect(result.address).toBe('');
      }),
      { numRuns: 500, seed: 0xdead },
    );
  });

  /**
   * P3: Truncated valid XDR
   * Take a real challenge XDR and slice bytes off the end.
   * The parser must handle incomplete XDR without throwing.
   */
  it('P3: never throws for truncated XDR', async () => {
    const clientKeypair = Keypair.random();
    const validXDR = buildValidSignedXDR(clientKeypair);
    // validXDR is base64; decode, truncate raw bytes, re-encode
    const validBytes = Buffer.from(validXDR, 'base64');

    const truncatedArb = fc
      .integer({ min: 0, max: Math.max(0, validBytes.length - 1) })
      .map((cutAt) => validBytes.slice(0, cutAt).toString('base64'));

    await fc.assert(
      fc.asyncProperty(truncatedArb, async (truncatedInput) => {
        const result = await verifyChallenge(truncatedInput, verifyOpts);
        assertValidResult(result);
        // Truncated XDR can never be a valid signed challenge
        expect(result.valid).toBe(false);
        expect(result.address).toBe('');
      }),
      { numRuns: 200, seed: 0xbeef },
    );
  });

  /**
   * P4: Bit-flipped valid XDR
   * Take a real challenge XDR, randomly flip a single bit anywhere in the
   * payload. The verification must fail cleanly — no throws, no valid=true
   * (collision probability is negligible).
   */
  it('P4: never throws for single-bit-flipped XDR', async () => {
    const clientKeypair = Keypair.random();
    const validXDR = buildValidSignedXDR(clientKeypair);
    const validBytes = Buffer.from(validXDR, 'base64');

    const flippedArb = fc
      .integer({ min: 0, max: validBytes.length - 1 })
      .chain((byteIndex) =>
        fc
          .integer({ min: 0, max: 7 })
          .map((bitIndex) => {
            const corrupted = Buffer.from(validBytes);
            corrupted[byteIndex] ^= 1 << bitIndex;
            return corrupted.toString('base64');
          }),
      );

    await fc.assert(
      fc.asyncProperty(flippedArb, async (corruptedInput) => {
        const result = await verifyChallenge(corruptedInput, verifyOpts);
        assertValidResult(result);
        // A bit-flip anywhere in the XDR should always fail verification
        expect(result.valid).toBe(false);
      }),
      { numRuns: 200, seed: 0xf00d },
    );
  });

  /**
   * P5: Edge cases — empty string, whitespace, null bytes, very long strings
   * Targeted fixed-value edge cases that property engines can miss if they
   * don't generate degenerate values in the first few runs.
   */
  it('P5: handles edge-case inputs without throwing', async () => {
    const edgeCases = [
      '',
      ' ',
      '\t\n\r',
      '\0',
      '\0'.repeat(256),
      'a',
      '=',
      '====',
      'AAAA',
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      // unicode
      '你好世界',
      '🚀🌕',
      // control characters
      '\x01\x02\x03',
      // very long — ensure no stack overflow on large inputs
      'A'.repeat(100_000),
    ];

    for (const input of edgeCases) {
      const result = await verifyChallenge(input, verifyOpts);
      assertValidResult(result);
      expect(result.valid).toBe(false);
    }
  });

  /**
   * P6: Return-type contract on valid inputs
   * Even on genuinely valid signed XDRs the result shape contract must hold,
   * and error must be absent (not merely undefined).
   */
  it('P6: valid signed XDR returns { valid: true, address: G..., no error }', async () => {
    const clientKeypair = Keypair.random();
    const validXDR = buildValidSignedXDR(clientKeypair);

    const result = await verifyChallenge(validXDR, verifyOpts);
    assertValidResult(result);
    expect(result.valid).toBe(true);
    expect(result.address).toBe(clientKeypair.publicKey());
    expect(result.error).toBeUndefined();
  });

  /**
   * P7: Garbage with correct base64 padding
   * Base64-encoded random bytes with exactly the right number of padding
   * chars — this exercises a slightly different code path than raw arbitrary
   * strings because the base64 decode succeeds but XDR parsing fails.
   */
  it('P7: never throws for correctly-padded random-byte base64', async () => {
    // Build strings whose raw byte count is a multiple of 3 so there's no
    // padding character to complain about; then also test the 1/2 remainder
    // cases explicitly to cover all padding variants.
    const paddingArb = fc
      .tuple(
        fc.uint8Array({ minLength: 48, maxLength: 512 }),
        fc.integer({ min: 0, max: 2 }),
      )
      .map(([bytes, extra]) => {
        // Trim to make length ≡ extra (mod 3) to exercise 0/1/2-byte remainders
        const trimmed = bytes.slice(0, bytes.length - ((bytes.length - extra) % 3));
        return Buffer.from(trimmed).toString('base64');
      });

    await fc.assert(
      fc.asyncProperty(paddingArb, async (input) => {
        const result = await verifyChallenge(input, verifyOpts);
        assertValidResult(result);
        expect(result.valid).toBe(false);
        expect(result.address).toBe('');
      }),
      { numRuns: 300, seed: 0xceed },
    );
  });

  /**
   * P8: Null/undefined coercion attempts via String wrappers
   * JavaScript callers might accidentally pass null, undefined, numbers, or
   * objects.  verifyChallenge is typed as (string, …) but in real-world
   * Express routes the value comes from req.header() which could behave
   * unexpectedly.  Verify the implementation is robust against implicit
   * coercions that TypeScript can't prevent at runtime.
   */
  it('P8: never throws for non-string-like runtime values coerced to strings', async () => {
    const nonStrings: unknown[] = [null, undefined, 0, -1, NaN, Infinity, {}, [], true, false];

    for (const value of nonStrings) {
      // Cast to string as a hostile caller would; verify no throw
      const result = await verifyChallenge(String(value), verifyOpts);
      assertValidResult(result);
      expect(result.valid).toBe(false);
    }
  });
});
