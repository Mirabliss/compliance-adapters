/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * sep10.ts — Client-side SEP-10 authentication helpers.
 *
 * Implements the three-step browser flow:
 *   1. GET  /auth?account=<G...>   → { transaction, network_passphrase }
 *   2. Sign the XDR transaction with Freighter
 *   3. POST /auth  { transaction: <signed XDR> }  → { token }
 *
 * The token is stored in sessionStorage so it survives page refreshes within
 * the same browser tab but is discarded when the tab is closed.
 */

import {
  isConnected,
  isAllowed,
  requestAccess,
  getAddress,
  signTransaction,
} from '@stellar/freighter-api';
import { Networks } from '@stellar/stellar-sdk';

// ── Constants ─────────────────────────────────────────────────────────────

/** sessionStorage key under which the JWT is persisted. */
export const TOKEN_STORAGE_KEY = 'sep10_token';

/**
 * Network passphrase injected at build time via Vite's `import.meta.env`.
 * Falls back to testnet when not set.
 */
const NETWORK_PASSPHRASE: string =
  (import.meta.env.VITE_NETWORK_PASSPHRASE as string | undefined) ?? Networks.TESTNET;

// ── Types ─────────────────────────────────────────────────────────────────

export interface ChallengeResponse {
  transaction: string;
  network_passphrase: string;
}

export interface SubmitResponse {
  token: string;
}

export interface Sep10Session {
  address: string;
  token: string;
  networkPassphrase: string;
}

// ── Freighter helpers ──────────────────────────────────────────────────────

/**
 * Checks whether the Freighter extension is installed and accessible.
 * Returns true / false — never throws.
 */
export async function isFreighterAvailable(): Promise<boolean> {
  try {
    const result = await isConnected();
    // @stellar/freighter-api v2 returns { isConnected: boolean } or boolean
    if (typeof result === 'object' && result !== null && 'isConnected' in result) {
      return (result as { isConnected: boolean }).isConnected;
    }
    return Boolean(result);
  } catch {
    return false;
  }
}

/**
 * Returns the currently selected Freighter public key after requesting access
 * if needed. Throws a descriptive error if the extension is not found or the
 * user denies access.
 */
export async function connectFreighter(): Promise<string> {
  const available = await isFreighterAvailable();
  if (!available) {
    throw new Error(
      'Freighter extension not found. Install it from https://www.freighter.app/ and reload.',
    );
  }

  // isAllowed() returns true when the current origin is already trusted.
  let allowed: boolean;
  try {
    const result = await isAllowed();
    allowed =
      typeof result === 'object' && result !== null && 'isAllowed' in result
        ? (result as { isAllowed: boolean }).isAllowed
        : Boolean(result);
  } catch {
    allowed = false;
  }

  if (!allowed) {
    // Ask the user to grant the page access to Freighter.
    const accessResult = await requestAccess();
    if (typeof accessResult === 'object' && accessResult !== null && 'error' in accessResult) {
      throw new Error(`Freighter access denied: ${(accessResult as { error: string }).error}`);
    }
    // If requestAccess returns a string address directly, that's the public key.
  }

  // Retrieve the currently selected address.
  const addressResult = await getAddress();
  if (typeof addressResult === 'object' && addressResult !== null) {
    const r = addressResult as { address?: string; error?: string };
    if (r.error) throw new Error(`Freighter getAddress error: ${r.error}`);
    if (r.address) return r.address;
  }
  // Legacy API returns the address string directly.
  if (typeof addressResult === 'string' && addressResult.startsWith('G')) {
    return addressResult;
  }

  throw new Error('Could not retrieve Stellar address from Freighter.');
}

// ── SEP-10 flow ────────────────────────────────────────────────────────────

/**
 * Step 1 — Fetch a challenge transaction from the server.
 *
 * The server is expected to expose:
 *   GET /auth?account=<G...>
 *   → 200 { transaction: "<base64 XDR>", network_passphrase: "<passphrase>" }
 */
export async function fetchChallenge(account: string): Promise<ChallengeResponse> {
  const url = `/auth?account=${encodeURIComponent(account)}`;
  const res = await fetch(url);
  if (!res.ok) {
    let detail = '';
    try {
      const body = (await res.json()) as { error?: string };
      detail = body.error ? `: ${body.error}` : '';
    } catch {
      /* ignore */
    }
    throw new Error(`Challenge fetch failed (${res.status})${detail}`);
  }
  const data = (await res.json()) as ChallengeResponse;
  if (!data.transaction || !data.network_passphrase) {
    throw new Error('Server returned an invalid challenge response (missing fields).');
  }
  return data;
}

/**
 * Step 2 — Sign the challenge XDR with Freighter.
 *
 * Freighter's `signTransaction` expects the XDR string and network details.
 * Returns the signed XDR string.
 */
export async function signChallenge(
  transactionXdr: string,
  accountAddress: string,
): Promise<string> {
  const result = await signTransaction(transactionXdr, {
    networkPassphrase: NETWORK_PASSPHRASE,
    accountToSign: accountAddress,
  });

  // signTransaction returns either the signed XDR directly or an object
  // with { signedTransaction } / { error }.
  if (typeof result === 'string') {
    return result;
  }
  if (typeof result === 'object' && result !== null) {
    const r = result as { signedTransaction?: string; error?: string };
    if (r.error) throw new Error(`Freighter signing error: ${r.error}`);
    if (r.signedTransaction) return r.signedTransaction;
  }
  throw new Error('Unexpected response from Freighter signTransaction.');
}

/**
 * Step 3 — Submit the signed transaction to the server and get back a JWT.
 *
 * The server is expected to expose:
 *   POST /auth  { transaction: "<signed XDR>" }
 *   → 200 { token: "<JWT>" }
 */
export async function submitChallenge(signedTransaction: string): Promise<string> {
  const res = await fetch('/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ transaction: signedTransaction }),
  });

  if (!res.ok) {
    let detail = '';
    try {
      const body = (await res.json()) as { error?: string };
      detail = body.error ? `: ${body.error}` : '';
    } catch {
      /* ignore */
    }
    throw new Error(`Challenge submission failed (${res.status})${detail}`);
  }

  const data = (await res.json()) as SubmitResponse;
  if (!data.token) {
    throw new Error('Server returned a successful response but no token.');
  }
  return data.token;
}

// ── High-level orchestration ───────────────────────────────────────────────

/**
 * Runs the complete SEP-10 flow:
 *   connect → fetchChallenge → signChallenge → submitChallenge → storeToken
 *
 * Returns a {@link Sep10Session} with the verified address, the JWT, and the
 * network passphrase so callers can display them to the user.
 *
 * @param onProgress  Optional callback invoked at each step with a human-
 *                    readable label so the UI can update progress indicators.
 */
export async function runSep10Login(
  onProgress?: (step: 'connect' | 'challenge' | 'sign' | 'submit') => void,
): Promise<Sep10Session> {
  // 1. Connect Freighter and obtain the public key.
  onProgress?.('connect');
  const address = await connectFreighter();

  // 2. Fetch the challenge from the server.
  onProgress?.('challenge');
  const { transaction, network_passphrase: networkPassphrase } = await fetchChallenge(address);

  // 3. Ask Freighter to sign the challenge XDR.
  onProgress?.('sign');
  const signedTransaction = await signChallenge(transaction, address);

  // 4. Submit the signed transaction and receive the JWT.
  onProgress?.('submit');
  const token = await submitChallenge(signedTransaction);

  // Persist the token for the lifetime of the browser tab.
  sessionStorage.setItem(TOKEN_STORAGE_KEY, token);

  return { address, token, networkPassphrase };
}

// ── Session helpers ────────────────────────────────────────────────────────

/**
 * Returns the stored JWT, or null if the user is not authenticated.
 */
export function getStoredToken(): string | null {
  return sessionStorage.getItem(TOKEN_STORAGE_KEY);
}

/**
 * Removes the stored JWT and clears Freighter's cached address (if possible).
 * This is a client-side logout; it does NOT call a server-side revocation
 * endpoint. Wire `POST /auth/revoke` yourself if you need server-side
 * invalidation (the full-stack-demo exposes this endpoint).
 */
export function clearSession(): void {
  sessionStorage.removeItem(TOKEN_STORAGE_KEY);
}
