import { Account, Keypair, MuxedAccount, Networks, Transaction } from '@stellar/stellar-sdk';
import {
  generateChallenge,
  InvalidClientAddressError,
  InvalidDomainError,
  InvalidMemoError,
  InvalidTimeoutError,
  MemoWithMuxedAccountError,
  ServerKeypairCannotSignError,
} from '../src/challenge';

describe('generateChallenge', () => {
  const homeDomain = 'localhost:3000';

  it('builds a challenge transaction for the given client address', () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();

    const before = Date.now();
    const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair, {
      homeDomain,
      webAuthDomain: homeDomain,
      networkPassphrase: Networks.TESTNET,
      timeoutSeconds: 300,
    });
    const after = Date.now();

    expect(typeof challenge.transactionXDR).toBe('string');
    expect(challenge.networkPassphrase).toBe(Networks.TESTNET);

    const tx = new Transaction(challenge.transactionXDR, Networks.TESTNET);
    expect(tx).toBeDefined();

    expect(challenge.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 300 * 1000);
    expect(challenge.expiresAt.getTime()).toBeLessThanOrEqual(after + 300 * 1000 + 50);
  });

  it('defaults homeDomain, webAuthDomain and networkPassphrase when omitted', () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();

    const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair);

    expect(challenge.networkPassphrase).toBe(Networks.TESTNET);
    expect(challenge.transactionXDR.length).toBeGreaterThan(0);
  });

  it('round-trips a custom memo into the built challenge transaction', () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();
    const memo = '123456789';

    const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair, {
      homeDomain,
      webAuthDomain: homeDomain,
      networkPassphrase: Networks.TESTNET,
      memo,
    });

    const tx = new Transaction(challenge.transactionXDR, Networks.TESTNET);

    expect(tx.memo.type).toBe('id');
    expect(tx.memo.value).toBe(memo);
  });

  it('omits the memo from the built transaction when not provided', () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();

    const challenge = generateChallenge(clientKeypair.publicKey(), serverKeypair, {
      homeDomain,
      webAuthDomain: homeDomain,
      networkPassphrase: Networks.TESTNET,
    });

    const tx = new Transaction(challenge.transactionXDR, Networks.TESTNET);

    expect(tx.memo.type).toBe('none');
    expect(tx.memo.value).toBeNull();
  });

  it('throws InvalidClientAddressError when clientAddress is not a valid Stellar Ed25519 public key', () => {
    const serverKeypair = Keypair.random();
    const invalidAddress = 'invalid-address';

    expect(() => generateChallenge(invalidAddress, serverKeypair)).toThrow(
      InvalidClientAddressError,
    );
  });

  it('throws ServerKeypairCannotSignError when serverKeypair has no secret key', () => {
    const publicOnly = Keypair.fromPublicKey(Keypair.random().publicKey());

    expect(() => generateChallenge(Keypair.random().publicKey(), publicOnly)).toThrow(
      ServerKeypairCannotSignError,
    );
  });

  it('warns when using default homeDomain in production environment (issue #303)', () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();
    const mockLogger = { warn: jest.fn(), debug: jest.fn(), info: jest.fn() };

    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    try {
      generateChallenge(clientKeypair.publicKey(), serverKeypair, {
        networkPassphrase: Networks.TESTNET,
        logger: mockLogger as any,
      });

      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('default homeDomain'),
        expect.anything(),
      );
    } finally {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  it('does not warn when an explicit homeDomain is provided', () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();
    const mockLogger = { warn: jest.fn(), debug: jest.fn(), info: jest.fn() };

    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    try {
      generateChallenge(clientKeypair.publicKey(), serverKeypair, {
        homeDomain: 'example.com',
        webAuthDomain: 'example.com',
        networkPassphrase: Networks.TESTNET,
        logger: mockLogger as any,
      });

      expect(mockLogger.warn).not.toHaveBeenCalled();
    } finally {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  it('does not warn in development environment even with default homeDomain', () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();
    const mockLogger = { warn: jest.fn(), debug: jest.fn(), info: jest.fn() };

    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    try {
      generateChallenge(clientKeypair.publicKey(), serverKeypair, {
        networkPassphrase: Networks.TESTNET,
        logger: mockLogger as any,
      });

      expect(mockLogger.warn).not.toHaveBeenCalled();
    } finally {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  it('does not warn in test environment even with default homeDomain', () => {
    const serverKeypair = Keypair.random();
    const clientKeypair = Keypair.random();
    const mockLogger = { warn: jest.fn(), debug: jest.fn(), info: jest.fn() };

    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'test';

    try {
      generateChallenge(clientKeypair.publicKey(), serverKeypair, {
        networkPassphrase: Networks.TESTNET,
        logger: mockLogger as any,
      });

      expect(mockLogger.warn).not.toHaveBeenCalled();
    } finally {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  it.each(['https://example.com', 'example.com/', 'example.com/path', 'exa mple.com'])(
    'rejects non-bare homeDomain %p',
    (bad) => {
      expect(() =>
        generateChallenge(Keypair.random().publicKey(), Keypair.random(), { homeDomain: bad }),
      ).toThrow(InvalidDomainError);
    },
  );

  it('rejects a non-bare webAuthDomain', () => {
    expect(() =>
      generateChallenge(Keypair.random().publicKey(), Keypair.random(), {
        homeDomain: 'example.com',
        webAuthDomain: 'https://example.com',
      }),
    ).toThrow(InvalidDomainError);
  });

  it.each(['abc', '12abc', '-1', '1.5', '', '18446744073709551616'])(
    'rejects invalid memo %p with InvalidMemoError',
    (memo) => {
      expect(() =>
        generateChallenge(Keypair.random().publicKey(), Keypair.random(), { memo }),
      ).toThrow(InvalidMemoError);
    },
  );

  it('accepts a valid uint64 memo', () => {
    expect(() =>
      generateChallenge(Keypair.random().publicKey(), Keypair.random(), {
        memo: '18446744073709551615',
      }),
    ).not.toThrow();
  });
});

describe('generateChallenge timeoutSec', () => {
  const opts = { homeDomain: 'localhost:3000', webAuthDomain: 'localhost:3000' };

  function windowOf(xdrString: string): number {
    const { timeBounds } = new Transaction(xdrString, Networks.TESTNET);
    return Number(timeBounds!.maxTime) - Number(timeBounds!.minTime);
  }

  it('defaults the validity window to 900 seconds', () => {
    const challenge = generateChallenge(Keypair.random().publicKey(), Keypair.random(), opts);
    expect(windowOf(challenge.transactionXDR)).toBe(900);
  });

  it('reflects a custom timeoutSec in the timebounds and expiresAt', () => {
    const before = Date.now();
    const challenge = generateChallenge(Keypair.random().publicKey(), Keypair.random(), {
      ...opts,
      timeoutSec: 120,
    });
    expect(windowOf(challenge.transactionXDR)).toBe(120);
    expect(challenge.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 120 * 1000);
  });

  it('accepts the upper bound (3600) and the smallest positive value', () => {
    expect(windowOf(generateChallenge(Keypair.random().publicKey(), Keypair.random(), { ...opts, timeoutSec: 3600 }).transactionXDR)).toBe(3600);
    expect(() =>
      generateChallenge(Keypair.random().publicKey(), Keypair.random(), { ...opts, timeoutSec: 1 }),
    ).not.toThrow();
  });

  it.each([0, -1, 3601, NaN, Infinity])('rejects timeoutSec = %p', (timeoutSec) => {
    expect(() =>
      generateChallenge(Keypair.random().publicKey(), Keypair.random(), { ...opts, timeoutSec }),
    ).toThrow(InvalidTimeoutError);
  });

  it('still honours the deprecated timeoutSeconds alias, and validates it', () => {
    const challenge = generateChallenge(Keypair.random().publicKey(), Keypair.random(), {
      ...opts,
      timeoutSeconds: 300,
    });
    expect(windowOf(challenge.transactionXDR)).toBe(300);
    expect(() =>
      generateChallenge(Keypair.random().publicKey(), Keypair.random(), { ...opts, timeoutSeconds: 7200 }),
    ).toThrow(InvalidTimeoutError);
  });
});

describe('generateChallenge muxed client accounts', () => {
  const opts = { homeDomain: 'localhost:3000', webAuthDomain: 'localhost:3000' };
  const base = Keypair.random();
  const muxedAddress = new MuxedAccount(new Account(base.publicKey(), '0'), '42').accountId();

  it('accepts an M-address and uses it as the client operation source', () => {
    const challenge = generateChallenge(muxedAddress, Keypair.random(), opts);
    const tx = new Transaction(challenge.transactionXDR, Networks.TESTNET);
    expect(tx.operations[0].source).toBe(muxedAddress);
  });

  it('throws a typed error when a memo is combined with a muxed account', () => {
    expect(() => generateChallenge(muxedAddress, Keypair.random(), { ...opts, memo: '1' })).toThrow(
      MemoWithMuxedAccountError,
    );
  });

  it('still rejects malformed addresses', () => {
    expect(() => generateChallenge('M' + 'A'.repeat(68), Keypair.random(), opts)).toThrow(
      InvalidClientAddressError,
    );
  });
});

