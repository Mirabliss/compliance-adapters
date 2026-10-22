/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { MuxedAccount, Networks, Operation, Transaction, WebAuth } from '@stellar/stellar-sdk';
import { assertBareDomain } from './challenge';
import { isValidStellarAddress } from '@compliance-adapters/shared';

/**
 * Subset of the Stellar account record needed for SEP-10 threshold verification.
 * Mirrors the fields returned by Horizon's `GET /accounts/{id}` under
 * `thresholds` and `signers`, but defined locally so callers don't need to
 * depend on `@stellar/stellar-sdk`'s `ServerApi` namespace.
 */
export interface AccountRecord {
  /** The account's Stellar address (G...). */
  account_id: string;
  /** Account-level thresholds: `low_threshold`, `med_threshold`, `high_threshold`. */
  thresholds: {
    low_threshold: number;
    med_threshold: number;
    high_threshold: number;
  };
  /** The account's signers with their weights. */
  signers: Array<{
    key: string;
    weight: number;
    type: string;
  }>;
}

/**
 * Loads a Stellar account from the ledger (e.g. a wrapper around Horizon's
 * `server.loadAccount()`). Returns `null` when the account does not exist on
 * the ledger (so verification falls back to the master-key check, per SEP-10).
 *
 * Any other error (network failure, rate limit, etc.) should reject; it will
 * surface as a verification error with an appropriate {@link VerifyErrorCode}.
 */
export type AccountLoader = (accountId: string) => Promise<AccountRecord | null>;

export interface VerifyChallengeOptions {
  serverAccountId: string;
  networkPassphrase?: string;
  homeDomains: string | string[];
  webAuthDomain: string | string[];
  /**
   * Optional expected memo for the signed challenge transaction. If set,
   * verification will fail if the transaction's memo does not match.
   * Useful for replay protection (e.g., tying a challenge to a specific
   * session or request ID).
   *
   * Expected encoding depends on the transaction's memo type: the plain string
   * for `text` and `id` memos, and a hex string (case-insensitive) for `hash`
   * and `return` memos.
   */
  expectedMemo?: string;
  /**
   * Extra clock-skew tolerance in seconds, applied symmetrically to both
   * timebounds (`minTime - tolerance` and `maxTime + tolerance`) on top of the
   * 300-second grace window `WebAuth.readChallengeTx` already applies. Must be
   * finite and non-negative; an invalid value fails verification with
   * `INVALID_OPTIONS`. Defaults to `0` (no extra tolerance).
   */
  clockSkewToleranceSec?: number;
  /**
   * Optional callback that loads the client account from the ledger (e.g. a
   * Horizon `loadAccount` wrapper). When provided, `verifyChallenge` verifies
   * the challenge signatures against the account's on-ledger signer set and the
   * medium threshold, as SEP-10 requires for existing accounts.
   *
   * When the account does not exist (`null` is returned), verification falls
   * back to the master-key check (the client's `G...` address must have signed
   * the challenge), which is the SEP-10 behaviour for accounts not yet on the
   * ledger.
   *
   * When omitted, verification always uses the master-key check — this is the
   * original behaviour and is safe for single-signer accounts whose master key
   * weight meets the medium threshold, but will reject valid multisig
   * accounts and will accept accounts whose master key has weight 0 (see
   * issue #762).
   */
  accountLoader?: AccountLoader;
}

// Grace window WebAuth.readChallengeTx hard-codes when validating timebounds.
const SDK_TIMEBOUNDS_GRACE_SEC = 60 * 5;

/**
 * Runs `fn` with `Date.now()` clamped into the challenge's own timebounds when the
 * current time falls within the SDK grace window plus `toleranceSec`. The SDK
 * offers no way to widen its grace window, so this lets the extra tolerance take
 * effect without re-implementing challenge verification. Outside the widened
 * window, or when the XDR cannot be parsed, `fn` runs against the real clock so
 * the SDK reports the failure itself.
 */
function withClockSkewTolerance<T>(
  signedTransactionXDR: string,
  networkPassphrase: string,
  toleranceSec: number,
  fn: () => T,
): T {
  if (toleranceSec === 0) return fn();

  let minTime: number;
  let maxTime: number;
  try {
    const tx = new Transaction(signedTransactionXDR, networkPassphrase);
    if (!tx.timeBounds) return fn();
    minTime = Number.parseInt(tx.timeBounds.minTime, 10);
    maxTime = Number.parseInt(tx.timeBounds.maxTime, 10);
  } catch {
    return fn();
  }

  const realNow = Date.now;
  const nowSec = Math.floor(realNow() / 1000);
  const window = SDK_TIMEBOUNDS_GRACE_SEC + toleranceSec;
  if (nowSec < minTime - window || nowSec > maxTime + window) return fn();

  const clampedSec = Math.min(Math.max(nowSec, minTime), maxTime);
  Date.now = () => clampedSec * 1000;
  try {
    return fn();
  } finally {
    Date.now = realNow;
  }
}

/**
 * Stable, documented codes identifying why {@link verifyChallenge} failed.
 *
 * Codes are intentionally coarse-grained — they identify the category of
 * failure without leaking internal exception messages. The human-readable
 * {@link VerifyResult.error} field carries the full message.
 *
 * | Code | Meaning |
 * |------|---------|
 * | `INVALID_SERVER_ACCOUNT_ID` | `serverAccountId` option is not a valid Ed25519 public key. |
 * | `INVALID_OPTIONS` | `homeDomains` or `webAuthDomain` failed format validation (bare-domain check), or `clockSkewToleranceSec` is negative or not finite. |
 * | `INVALID_CHALLENGE` | The XDR could not be parsed, the transaction structure is wrong, or the server signature is missing/incorrect. |
 * | `CHALLENGE_EXPIRED` | The transaction's time-bounds have lapsed (including the SDK's built-in 300-second grace window). |
 * | `WRONG_SIGNER` | The transaction was not signed by the expected client account. |
 * | `WRONG_DOMAIN` | None of the supplied `webAuthDomain` values matched the challenge. |
 * | `MEMO_MISMATCH` | `expectedMemo` was supplied but the transaction carries a different (or absent) memo. |
 * | `UNKNOWN` | An unexpected error that does not map to any of the above categories. |
 */
export type VerifyErrorCode =
  | 'INVALID_SERVER_ACCOUNT_ID'
  | 'INVALID_OPTIONS'
  | 'INVALID_CHALLENGE'
  | 'CHALLENGE_EXPIRED'
  | 'WRONG_SIGNER'
  | 'WRONG_DOMAIN'
  | 'MEMO_MISMATCH'
  | 'UNKNOWN';

/**
 * The result of {@link verifyChallenge}.
 */
export interface VerifyResult {
  /** Whether the signed challenge transaction passed all SEP-10 checks. */
  valid: boolean;
  /** The authenticated Stellar account ID (client's master key), or `''` when `valid` is `false`. */
  address: string;
  /** The authenticated client account as signed in the challenge: a `G...` address, or a muxed `M...` address. Same value as {@link address}; empty when `valid` is `false`. */
  account?: string;
  /** The underlying `G...` account. Equals {@link account} unless the client account is muxed. */
  baseAccount?: string;
  /** The mux id (unsigned 64-bit, decimal string) of a muxed `M...` client account; absent for plain `G...` accounts. */
  muxedId?: string;
  /**
   * The wallet's client domain, present only when the challenge included a
   * `client_domain` ManageData operation (see {@link
   * GenerateChallengeOptions.clientDomain | generateChallenge's clientDomain
   * option}) and that domain's signing key co-signed the transaction.
   */
  clientDomain?: string;
  /**
   * Identifier of the verified token (`jti`): the hex-encoded hash of the
   * challenge transaction. Present only when `valid` is `true`. Pass it to
   * `RevocationStore.revokeToken` to sign out one session without affecting
   * the address's other sessions.
   */
  jti?: string;
  /** Human-readable reason verification failed, present only when `valid` is `false`. */
  error?: string;
  /**
   * Stable error code identifying the failure category, present only when
   * `valid` is `false`. Allows callers to branch on failure reason without
   * parsing the human-readable {@link error} string.
   *
   * See {@link VerifyErrorCode} for the full set of possible values.
   */
  errorCode?: VerifyErrorCode;
}

// Buffer#toString() defaults to utf8, which mangles the raw bytes of hash/return
// memos, so those are compared as hex instead.
function encodeMemo(memo: { type: string; value: unknown }): string {
  if (memo.value === null || memo.value === undefined) return '';
  if (Buffer.isBuffer(memo.value) || memo.value instanceof Uint8Array) {
    const buf = Buffer.from(memo.value);
    return memo.type === 'hash' || memo.type === 'return' ? buf.toString('hex') : buf.toString('utf8');
  }
  return String(memo.value);
}

/**
 * Classify an SDK or internal error into a {@link VerifyErrorCode}.
 *
 * The Stellar SDK does not expose a stable error class hierarchy that is safe
 * to `instanceof`-check, so we match on well-known substrings of the
 * error message. These patterns are derived from the SDK source and are
 * intentionally conservative: any message that does not match a known pattern
 * falls through to 'UNKNOWN'.
 */
function classifyError(err: unknown): VerifyErrorCode {
  const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();

  // Expired / timebounds
  if (msg.includes('expired') || msg.includes('timebounds') || msg.includes('time bounds')) {
    return 'CHALLENGE_EXPIRED';
  }
  // Signer-related failures
  if (
    msg.includes('no signers') ||
    msg.includes('not signed') ||
    msg.includes('signature') ||
    msg.includes('signer') ||
    msg.includes('multisig') ||
    msg.includes('signed by') ||
    msg.includes('signing key')
  ) {
    return 'WRONG_SIGNER';
  }
  // Domain confusion or web_auth_domain mismatch
  if (
    msg.includes('web_auth_domain') ||
    msg.includes('webauthdomainoperation') ||
    msg.includes('webauthdomainkeyvalue') ||
    msg.includes('home_domain') ||
    msg.includes('homedomain')
  ) {
    return 'WRONG_DOMAIN';
  }
  // XDR parsing / structural invalidity (network passphrase, malformed XDR, …)
  // Also covers memo-type constraint errors ("The transaction has a memo but…",
  // "The transaction's memo must be of type `id`") which the SDK throws as
  // InvalidChallengeError but whose messages contain neither a signer nor a
  // domain keyword.
  if (
    msg.includes('invalid') ||
    msg.includes('parse') ||
    msg.includes('xdr') ||
    msg.includes('network') ||
    msg.includes('passphrase') ||
    msg.includes('hash') ||
    msg.includes('sequence') ||
    msg.includes('source account') ||
    msg.includes('operation') ||
    msg.includes('memo')
  ) {
    return 'INVALID_CHALLENGE';
  }

  return 'UNKNOWN';
}

export async function verifyChallenge(
  signedTransactionXDR: string,
  options: VerifyChallengeOptions,
): Promise<VerifyResult> {
  if (!isValidStellarAddress(options.serverAccountId)) {
    return {
      valid: false,
      address: '',
      error: `sep10-auth: Invalid serverAccountId: ${options.serverAccountId}`,
      errorCode: 'INVALID_SERVER_ACCOUNT_ID',
    };
  }

  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET;
  const clockSkewToleranceSec = options.clockSkewToleranceSec ?? 0;
  if (!Number.isFinite(clockSkewToleranceSec) || clockSkewToleranceSec < 0) {
    return {
      valid: false,
      address: '',
      error: `sep10-auth: clockSkewToleranceSec must be a finite, non-negative number, got ${clockSkewToleranceSec}`,
      errorCode: 'INVALID_OPTIONS',
    };
  }
  const homeDomainList = Array.isArray(options.homeDomains)
    ? options.homeDomains
    : [options.homeDomains];
  const webAuthDomains = Array.isArray(options.webAuthDomain)
    ? options.webAuthDomain
    : [options.webAuthDomain];

  try {
    homeDomainList.forEach((d) => assertBareDomain('homeDomains', d));
    webAuthDomains.forEach((d) => assertBareDomain('webAuthDomain', d));
  } catch (error) {
    return { valid: false, address: '', error: (error as Error).message, errorCode: 'INVALID_OPTIONS' };
  }

  // The underlying SDK only matches against a single webAuthDomain per call,
  // so try each candidate in turn and succeed on the first match.
  let lastError: unknown;

  for (const webAuthDomain of webAuthDomains) {
    try {
      const { clientAccountID, tx } = withClockSkewTolerance(
        signedTransactionXDR,
        networkPassphrase,
        clockSkewToleranceSec,
        () =>
          WebAuth.readChallengeTx(
            signedTransactionXDR,
            options.serverAccountId,
            networkPassphrase,
            options.homeDomains,
            webAuthDomain,
          ),
      );

      // A muxed (M...) client account is signed for by its underlying G... key.
      const isMuxed = clientAccountID.startsWith('M');
      const muxed = isMuxed ? MuxedAccount.fromAddress(clientAccountID, '0') : undefined;
      const baseAccount = muxed ? muxed.baseAccount().accountId() : clientAccountID;

      // ── #762: on-ledger signer / threshold verification ─────────────────────
      // When an accountLoader is supplied, SEP-10 requires the server to load
      // the client account's signers from the ledger and verify that the
      // challenge signatures meet the medium threshold. If the account doesn't
      // exist on the ledger yet, fall back to the master-key check.
      if (options.accountLoader) {
        let account: AccountRecord | null;
        try {
          account = await options.accountLoader(baseAccount);
        } catch (loadError) {
          return {
            valid: false,
            address: '',
            error: `sep10-auth: accountLoader failed: ${loadError instanceof Error ? loadError.message : String(loadError)}`,
            errorCode: 'UNKNOWN',
          };
        }

        if (account) {
          // Account exists on ledger: verify against the on-ledger signer set
          // and the medium threshold.
          withClockSkewTolerance(signedTransactionXDR, networkPassphrase, clockSkewToleranceSec, () =>
            WebAuth.verifyChallengeTxThreshold(
              signedTransactionXDR,
              options.serverAccountId,
              networkPassphrase,
              account!.thresholds.med_threshold,
              account!.signers,
              options.homeDomains,
              webAuthDomain,
            ),
          );
        } else {
          // Account doesn't exist on the ledger: fall back to the master-key
          // check (the client's G... address must have signed the challenge).
          withClockSkewTolerance(signedTransactionXDR, networkPassphrase, clockSkewToleranceSec, () =>
            WebAuth.verifyChallengeTxSigners(
              signedTransactionXDR,
              options.serverAccountId,
              networkPassphrase,
              [baseAccount],
              options.homeDomains,
              webAuthDomain,
            ),
          );
        }
      } else {
        // No accountLoader: verify against the master key only (original
        // behaviour — safe for single-signer accounts but does not check
        // thresholds or multisig signer sets).
        withClockSkewTolerance(signedTransactionXDR, networkPassphrase, clockSkewToleranceSec, () =>
          WebAuth.verifyChallengeTxSigners(
            signedTransactionXDR,
            options.serverAccountId,
            networkPassphrase,
            [baseAccount],
            options.homeDomains,
            webAuthDomain,
          ),
        );
      }

      if (options.expectedMemo !== undefined) {
        const txMemo = encodeMemo(tx.memo);
        const isBinaryMemo = tx.memo.type === 'hash' || tx.memo.type === 'return';
        const matches = isBinaryMemo
          ? txMemo === options.expectedMemo.toLowerCase()
          : txMemo === options.expectedMemo;
        if (!matches) {
          return {
            valid: false,
            address: '',
            error: `sep10-auth: memo mismatch, expected "${options.expectedMemo}" but got "${txMemo}"`,
            errorCode: 'MEMO_MISMATCH',
          };
        }
      }

      const clientDomainOp = tx.operations.find(
        (op): op is Operation.ManageData => op.type === 'manageData' && op.name === 'client_domain',
      );
      const clientDomain = clientDomainOp?.value?.toString();

      return {
        valid: true,
        address: clientAccountID,
        jti: tx.hash().toString('hex'),
        ...(clientDomain ? { clientDomain } : {}),
      };
    } catch (error) {
      lastError = error;
    }
  }

  const errorCode = classifyError(lastError);
  return {
    valid: false,
    address: '',
    error: `sep10-auth: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
    errorCode,
  };
}
