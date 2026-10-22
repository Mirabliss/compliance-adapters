/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { StrKey } from '@stellar/stellar-sdk';

export { combineExpositions } from './metrics';
export {
  createSemaphore,
  SemaphoreTimeoutError,
} from './semaphore';
export type { Semaphore, SemaphoreAcquireOptions } from './semaphore';

/**
 * Validate a Stellar address (Ed25519 public key in StrKey `G...` format).
 * Thin wrapper around {@link https://developers.stellar.org/docs/start/list-of-operations-and-requests/ StrKey.isValidEd25519PublicKey}
 * from `@stellar/stellar-sdk`, centralised so all compliance-adapters packages
 * share the same validation logic without duplicating the `@stellar/stellar-sdk`
 * dependency.
 */
export function isValidStellarAddress(address: string): boolean {
  return StrKey.isValidEd25519PublicKey(address);
}

/**
 * Canonical form of a Stellar address: surrounding whitespace removed and
 * uppercased. Addresses arriving from CSV files, JSON input or REST providers
 * may be padded or lowercase; normalize them at every ingestion boundary so the
 * same account is never checked, cached or written twice under two spellings.
 * Does not validate — pair with {@link isValidStellarAddress}.
 */
export function normalizeStellarAddress(address: string): string {
  return address.trim().toUpperCase();
}

/**
 * Redact a Stellar address for logs: keeps the first 4 and last 4
 * characters (`GABC…WXYZ`) so log lines stay correlatable without
 * exposing the full account. Applies to `G` (ed25519), `M` (muxed)
 * and `C` (contract) addresses. Returns `[invalid-address]` for
 * non-string or too-short input.
 */
export function redactAddress(addr: unknown): string {
  if (typeof addr !== 'string' || addr.length < 8) {
    return '[invalid-address]';
  }
  return `${addr.slice(0, 4)}…${addr.slice(-4)}`;
}
