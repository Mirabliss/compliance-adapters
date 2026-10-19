/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * A store the SEP-10 middleware can consult to reject an otherwise-valid,
 * unexpired challenge transaction for a given Stellar address — e.g. because
 * an operator wants to cut off access immediately instead of waiting for the
 * challenge's `timeoutSeconds` to elapse naturally.
 */
export interface RevocationStore {
  /** Returns whether `address` is currently revoked. */
  isRevoked(address: string): boolean | Promise<boolean>;
  /**
   * Revokes `address`. If `until` is provided, the revocation expires at
   * that time; otherwise it remains in effect until {@link unrevoke} is called.
   */
  revoke(address: string, until?: Date): void | Promise<void>;
  /** Lifts a revocation previously set with {@link revoke}. */
  unrevoke(address: string): void | Promise<void>;
  /** Optionally enumerates the addresses that are currently revoked. */
  list?(): string[] | Promise<string[]>;
  /**
   * Revokes a single token by its identifier (`jti`) without affecting other
   * tokens of the same address. The entry expires automatically at
   * `expiresAt` (the token's own expiry), after which it is pruned.
   * Optional so address-only stores keep working; the middleware checks
   * {@link isTokenRevoked} only when it is implemented.
   */
  revokeToken?(jti: string, expiresAt: Date): void | Promise<void>;
  /** Returns whether the token identified by `jti` is currently revoked. */
  isTokenRevoked?(jti: string): boolean | Promise<boolean>;
}

/**
 * In-memory reference implementation of {@link RevocationStore}. Revocations
 * are held in a `Map` and are lost on process restart; suitable for a single
 * process or as a template for a persistent (e.g. Redis, database-backed) store.
 */
export interface InMemoryRevocationStoreOptions {
  /**
 * Maximum number of revocations to retain. When set and a new revocation
 * would exceed it, expired entries are reclaimed first, followed by temporary
 * revocations, and lastly permanent revocations in FIFO order.
 */
  maxEntries?: number;
}

export class InMemoryRevocationStore implements RevocationStore {
  private readonly revoked = new Map<string, Date | undefined>();
  private readonly revokedTokens = new Map<string, Date>();
  private readonly maxEntries?: number;

  constructor(options: InMemoryRevocationStoreOptions = {}) {
    this.maxEntries = options.maxEntries;
  }

  isRevoked(address: string): boolean {
    const until = this.revoked.get(address);
    if (until === undefined) {
      return this.revoked.has(address);
    }
    if (until.getTime() <= Date.now()) {
      this.revoked.delete(address);
      return false;
    }
    return true;
  }

  revoke(address: string, until?: Date): void {
    this.revoked.delete(address);
    this.revoked.set(address, until);

    if (this.maxEntries !== undefined && this.maxEntries >= 0) {
      if (this.maxEntries === 0) {
        this.revoked.clear();
        return;
      }

      // Step 1: Evict logically expired entries first
      if (this.revoked.size > this.maxEntries) {
        const now = Date.now();
        for (const [key, exp] of this.revoked) {
          if (exp !== undefined && exp.getTime() <= now) {
            this.revoked.delete(key);
            if (this.revoked.size <= this.maxEntries) {
              break;
            }
          }
        }
      }

      // Step 2: If still exceeding maxEntries, evict oldest temporary (expiring) entries next
      if (this.revoked.size > this.maxEntries) {
        for (const [key, exp] of this.revoked) {
          if (exp !== undefined) {
            this.revoked.delete(key);
            if (this.revoked.size <= this.maxEntries) {
              break;
            }
          }
        }
      }

      // Step 3: If still exceeding maxEntries, evict oldest permanent entries as fallback
      while (this.revoked.size > this.maxEntries) {
        const oldestKey = this.revoked.keys().next().value;
        if (oldestKey === undefined) break;
        this.revoked.delete(oldestKey);
      }
    }
  }

  unrevoke(address: string): void {
    this.revoked.delete(address);
  }

  /**
   * Revokes the single token identified by `jti` until `expiresAt`. Expired
   * token revocations are pruned on every call, so the map never retains a
   * token past its own expiry.
   */
  revokeToken(jti: string, expiresAt: Date): void {
    this.pruneExpiredTokens();
    if (expiresAt.getTime() <= Date.now()) {
      return;
    }
    this.revokedTokens.set(jti, expiresAt);
  }

  isTokenRevoked(jti: string): boolean {
    const expiresAt = this.revokedTokens.get(jti);
    if (expiresAt === undefined) {
      return false;
    }
    if (expiresAt.getTime() <= Date.now()) {
      this.revokedTokens.delete(jti);
      return false;
    }
    return true;
  }

  /** Addresses currently revoked; expired timed revocations are excluded (and lazily evicted). */
  list(): string[] {
    return [...this.revoked.keys()].filter((address) => this.isRevoked(address));
  }

  /** Current number of tracked revocations (including any not yet lazily expired). */
  size(): number {
    return this.revoked.size;
  }

  /** Current number of tracked per-token revocations, after pruning expired ones. */
  tokenSize(): number {
    this.pruneExpiredTokens();
    return this.revokedTokens.size;
  }

  private pruneExpiredTokens(): void {
    const now = Date.now();
    for (const [jti, expiresAt] of this.revokedTokens) {
      if (expiresAt.getTime() <= now) {
        this.revokedTokens.delete(jti);
      }
    }
  }
}
