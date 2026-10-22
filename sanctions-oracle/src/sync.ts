/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import * as fs from 'fs';
import {
  Contract,
  Keypair,
  Transaction,
  FeeBumpTransaction,
  TransactionBuilder,
  BASE_FEE,
  nativeToScVal,
  rpc,
} from '@stellar/stellar-sdk';
import { isValidStellarAddress, normalizeStellarAddress } from '@compliance-adapters/shared';
import { type Logger, noopLogger, consoleLogger } from '@compliance-adapters/logger';
export type { Logger } from '@compliance-adapters/logger';
import { SanctionsProvider } from './SanctionsProvider';
import { SyncCheckpointStore, FileCheckpointStore } from './checkpoint';
import { createJsonlAuditLogger } from './auditLog';
import { MockSanctionsProvider } from './mockProvider';
import { CsvSanctionsProvider } from './csvProvider';
import { RateLimitedSanctionsProvider } from './rateLimitedProvider';
import { type AnyTracer, NoopTracer } from './tracing';
import { type AnyMetricsRegistry, NoopMetricsRegistry } from './metrics';
import { withRetry, RetryOptions } from './retry';
import { type Signer, toSigner, signTransaction } from './signer';
import { computeBackoffDelayMs, BackoffOptions } from '@compliance-adapters/backoff';

interface CacheEntry {
  result: { flagged: boolean; source: string };
  timestamp: number;
}

/**
 * Optional cache layer for SanctionsProvider results.
 * Avoids redundant provider calls for addresses checked recently.
 */
export class ProviderResultCache {
  private cache: Map<string, CacheEntry> = new Map();
  private readonly ttlMs: number;
  private readonly maxEntries?: number;
  private readonly inFlight = new Map<string, Promise<{ flagged: boolean; source: string }>>();

  /**
   * Create a result cache with a specified time-to-live (TTL).
   * @param ttlMs Time-to-live for cached results in milliseconds
   * @param maxEntries Optional maximum number of entries to retain. When set,
   * the least-recently-used entry is evicted once the cache would exceed this size.
   */
  constructor(ttlMs: number = 3600000, maxEntries?: number) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
  }

  /**
   * Get a cached result if available and not expired.
   * @returns The cached result, or undefined if not found or expired
   */
  get(address: string): { flagged: boolean; source: string } | undefined {
    const entry = this.cache.get(address);
    if (!entry) return undefined;

    const now = Date.now();
    if (now - entry.timestamp > this.ttlMs) {
      this.cache.delete(address);
      return undefined;
    }

    // Refresh recency for LRU eviction.
    this.cache.delete(address);
    this.cache.set(address, entry);

    return entry.result;
  }

  /**
   * Store a result in the cache.
   */
  set(address: string, result: { flagged: boolean; source: string }): void {
    this.cache.delete(address);
    this.cache.set(address, {
      result,
      timestamp: Date.now(),
    });

    if (this.maxEntries !== undefined) {
      while (this.cache.size > this.maxEntries) {
        const oldestKey = this.cache.keys().next().value;
        if (oldestKey === undefined) break;
        this.cache.delete(oldestKey);
      }
    }
  }

  /**
   * Remove a single cached entry, e.g. after an operator determines it's stale.
   * @returns Whether an entry was present and removed.
   */
  delete(address: string): boolean {
    return this.cache.delete(address);
  }

  /**
   * Retrieve a cached result or coalesce concurrent misses behind a single
   * in-flight promise, so concurrent lookups for the same address do not race to
   * populate the cache with duplicate provider calls.
   */
  async getOrLoad(
    address: string,
    load: () => Promise<{ flagged: boolean; source: string }>,
  ): Promise<{ flagged: boolean; source: string }> {
    const cached = this.get(address);
    if (cached) {
      return cached;
    }

    const existing = this.inFlight.get(address);
    if (existing) {
      return existing;
    }

    let resolve!: (value: { flagged: boolean; source: string }) => void;
    let reject!: (reason?: unknown) => void;
    const next = new Promise<{ flagged: boolean; source: string }>((res, rej) => {
      resolve = res;
      reject = rej;
    });

    this.inFlight.set(address, next);

    (async () => {
      try {
        const result = await load();
        this.set(address, result);
        resolve(result);
      } catch (error) {
        reject(error);
      } finally {
        const current = this.inFlight.get(address);
        if (current === next) {
          this.inFlight.delete(address);
        }
      }
    })();

    return next;
  }

  /**
   * Clear all cached entries.
   */
  clear(): void {
    this.cache.clear();
    this.inFlight.clear();
  }
}

export interface AuditLogEntry {
  /** The address added to (or, when `action` is `'remove'`, removed from) the denylist. */
  address: string;
  /**
   * Set to `'remove'` for a delisting recorded by reconcile mode. Absent for
   * additions, which keeps existing audit consumers unchanged.
   */
  action?: 'remove';
  /** Timestamp when the write occurred (ISO 8601 string). */
  timestamp: string;
  /**
   * The source watchlist that flagged the address. For a removal, the provider
   * source that reported the address as cleared.
   */
  source: string;
  /** The transaction hash resulting from the write. */
  txHash: string;
}

export type AuditLogger = (entry: AuditLogEntry) => void | Promise<void>;

export interface DenylistWriter {
  addToDenylist(address: string): Promise<{ hash: string }>;
  /**
   * Removes an address from the on-chain denylist (`remove_from_denylist`).
   * Optional; a live reconcile run ({@link SyncOptions.reconcile}) requires
   * this or {@link DenylistWriter.removeFromDenylistWithSource}.
   */
  removeFromDenylist?(address: string): Promise<{ hash: string }>;
  /** Like {@link DenylistWriter.removeFromDenylist}, also recording the clearing provider `source` for audit purposes. */
  removeFromDenylistWithSource?(
    address: string,
    source: string,
  ): Promise<{ hash: string; auditLog?: AuditLogEntry }>;
}

export interface SyncOptions {
  provider: SanctionsProvider;
  /**
   * Candidate addresses to check. In a real deployment this might come
   * from a chain scan or an existing account list; here it's just an
   * injected array so this function stays pure and easily testable
   * without a network dependency.
   */
  addresses: string[];
  writer: DenylistWriter;
  dryRun?: boolean;
  /** Retry-with-backoff config applied around each provider.checkAddress call. */
  retry?: RetryOptions;
  /**
   * Optional cache to avoid redundant provider lookups for recently checked addresses.
   * If provided, results are cached with a configurable TTL.
   */
  cache?: ProviderResultCache;
  /**
   * Optional logger for progress logging during large address syncs.
   * If provided, logs will be emitted periodically (every progressInterval addresses).
   */
  logger?: Logger;
  /**
   * Number of addresses to process before emitting a progress log.
   * Defaults to 100 if logger is provided.
   */
  progressInterval?: number;
  /**
   * Optional concurrency limit for provider.checkAddress calls.
   * If provided, limits the number of concurrent address checks.
   * Defaults to unlimited (sequential processing).
   */
  concurrency?: number;
  /**
   * Optional current denylist contents. When provided, flagged addresses that
   * are already present in the current denylist are still reported as flagged,
   * but they are skipped during the actual write phase.
   */
  currentDenylist?: string[];
  /**
   * Opt-in delisting. When true, every address in {@link SyncOptions.currentDenylist}
   * (the on-chain denylist or a last snapshot) is re-checked with the provider,
   * and those the provider no longer flags are removed from the denylist via the
   * writer's `removeFromDenylist`. Addresses whose check fails are never removed.
   * With `dryRun` the planned removals are reported in
   * {@link SyncResult.plannedRemovals} and nothing is removed. Each removal is
   * audit-logged with the provider source. Defaults to false: sync only adds.
   */
  reconcile?: boolean;
  /**
   * Optional metrics registry.  Pass a `MetricsRegistry` instance to record
   * per-phase counters and latency histograms for `address_check` and
   * `denylist_write` operations.  When omitted all instrumentation is a no-op.
   */
  metrics?: AnyMetricsRegistry;
  /**
   * Optional tracer for OpenTelemetry-compatible distributed tracing.
   * When omitted, a no-op tracer is used — zero overhead and no exports.
   *
   * Stellar addresses are NOT attached to spans unless
   * `TracingOptions.redactPayload` is explicitly set to `false` on the
   * tracer; the span will carry only phase and outcome attributes.
   */
  tracer?: AnyTracer;
  /**
   * Optional checkpoint store that makes a large sync resumable after a crash.
   * As each address is finished, it is recorded via `checkpoint.markComplete`
   * (clean addresses right after the provider check; flagged addresses only
   * once the denylist write succeeds). Pass {@link SyncOptions.resume} on a
   * later run to skip everything already recorded.
   */
  checkpoint?: CheckpointStore | SyncCheckpointStore;
  /**
   * When true and a {@link SyncOptions.checkpoint} is provided, addresses the
   * checkpoint already reports as complete are skipped (returned in
   * {@link SyncResult.skipped}) instead of being re-checked and re-written.
   * Defaults to false.
   */
  resume?: boolean;
  /**
   * Optional hard deadline for the run, in milliseconds. Once it passes, no
   * new provider checks are started; in-flight checks finish, already-flagged
   * addresses are written and checkpointed, and the result reports
   * `deadlineExceeded: true` with the untouched addresses in `unprocessed`.
   */
  maxDurationMs?: number;
}

/** CLI exit code used when a run stops because `--max-duration` elapsed. */
export const EXIT_CODE_DEADLINE_EXCEEDED = 3;

/**
 * A single address whose provider check failed on every retry attempt,
 * paired with the message from the last error that caused it to fail.
 */
export interface FailedAddress {
  address: string;
  /** Message of the final error thrown by `provider.checkAddress` (after retries). */
  error: string;
}

/**
 * Result of a sanctions sync operation.
 */
export interface SyncResult {
  /** Total number of candidate addresses checked against the provider. */
  checked: number;
  /** Addresses flagged by the sanctions provider. */
  flagged: string[];
  /** Addresses successfully written to the denylist (empty if dryRun is true). */
  written: string[];
  /**
   * Addresses whose provider check failed on every retry attempt.
   *
   * This is kept as a bare `string[]` for backward compatibility; use
   * {@link SyncResult.failedWithReasons} when you need the error message that
   * caused each failure (e.g. to distinguish rate-limit failures from genuine
   * provider errors programmatically).
   */
  failed: string[];
  /**
   * The same addresses as {@link SyncResult.failed}, each paired with the
   * message of the final error that caused it to fail.
   */
  failedWithReasons: FailedAddress[];
  /**
   * Input entries that are not valid Stellar Ed25519 public keys (StrKey
   * `G...`). These are never checked against the provider — a malformed entry
   * (typo, truncated paste, a non-Stellar identifier) is reported here rather
   * than silently landing in neither `flagged` nor `failed`.
   */
  invalid: string[];
  /**
   * Addresses skipped because a {@link SyncOptions.checkpoint} already recorded
   * them as complete and {@link SyncOptions.resume} was set. Empty otherwise.
   */
  skipped: string[];
  /** Whether this was a dry-run (read-only) operation. */
  dryRun: boolean;
  /**
   * Reconcile mode only: denylist addresses the provider has cleared and that
   * were successfully removed (empty if dryRun is true).
   */
  removed?: string[];
  /**
   * Reconcile mode only: denylist addresses the provider has cleared, i.e. the
   * removals that are planned (dry-run) or attempted (live), with the provider
   * source that cleared each.
   */
  plannedRemovals?: { address: string; source: string }[];
  /** Reconcile mode only: cleared addresses whose removal transaction failed. */
  failedRemovals?: FailedAddress[];
  /** True when {@link SyncOptions.maxDurationMs} elapsed before every address was checked. */
  deadlineExceeded?: boolean;
  /** Addresses never checked because the deadline elapsed. */
  unprocessed?: string[];
}

interface FlaggedAddressWithSource {
  address: string;
  source: string;
}

async function executeConcurrent<T>(
  items: T[],
  fn: (item: T) => Promise<void>,
  concurrency?: number,
  shouldStop: () => boolean = () => false,
): Promise<void> {
  if (!concurrency || concurrency >= items.length) {
    for (const item of items) {
      if (shouldStop()) return;
      await fn(item);
    }
    return;
  }

  const queue = [...items];
  const active: Promise<void>[] = [];

  while (queue.length > 0 || active.length > 0) {
    while (active.length < concurrency && queue.length > 0 && !shouldStop()) {
      const item = queue.shift()!;
      const promise = fn(item).then(() => {
        active.splice(active.indexOf(promise), 1);
      });
      active.push(promise);
    }

    if (active.length > 0) {
      await Promise.race(active);
    }
  }
}

export async function syncSanctionsToDenylist(options: SyncOptions): Promise<SyncResult> {
  const {
    provider,
    addresses,
    writer,
    dryRun = false,
    logger = noopLogger,
    retry,
    cache,
    progressInterval = 100,
    concurrency,
    currentDenylist = [],
    metrics = new NoopMetricsRegistry(),
    tracer = new NoopTracer(),
    checkpoint,
    resume = false,
    reconcile = false,
    maxDurationMs,
  } = options;
  const deadline = maxDurationMs !== undefined ? Date.now() + maxDurationMs : undefined;
  const pastDeadline = () => deadline !== undefined && Date.now() >= deadline;
  const started = new Set<string>();

  const legacyLogger = logger as Logger & { log?: (...args: unknown[]) => void };
  const safeLogger = {
    debug: (...args: unknown[]) =>
      typeof legacyLogger.debug === 'function'
        ? legacyLogger.debug(...args)
        : legacyLogger.log?.(...args),
    info: (...args: unknown[]) =>
      typeof legacyLogger.info === 'function'
        ? legacyLogger.info(...args)
        : legacyLogger.log?.(...args),
    warn: (...args: unknown[]) =>
      typeof legacyLogger.warn === 'function'
        ? legacyLogger.warn(...args)
        : legacyLogger.log?.(...args),
    error: (...args: unknown[]) =>
      typeof legacyLogger.error === 'function'
        ? legacyLogger.error(...args)
        : legacyLogger.log?.(...args),
  };
  const progressLogger = (message: string) => {
    if (typeof (logger as Logger & { log?: (...args: unknown[]) => void }).log === 'function') {
      (logger as Logger & { log?: (...args: unknown[]) => void }).log!(message);
      return;
    }
    safeLogger.debug(message);
  };

  safeLogger.info('sanctions-oracle: starting sync', { total: addresses.length, dryRun });

  if (
    reconcile &&
    !dryRun &&
    !writer.removeFromDenylist &&
    !writer.removeFromDenylistWithSource
  ) {
    throw new Error(
      'sanctions-oracle: reconcile requires a writer that implements removeFromDenylist',
    );
  }

  // Reject malformed input up front so a typo / truncated paste / non-Stellar
  // identifier is reported distinctly instead of being checked and quietly
  // landing in neither `flagged` nor `failed`. Valid input is normalized
  // (trimmed, uppercased) first so one account maps to one canonical address
  // for the provider lookup, the cache key and the denylist write.
  const normalizedInput = addresses.map(normalizeStellarAddress);
  const invalid: string[] = [];
  const validAddresses: string[] = [];
  const seenValid = new Set<string>();
  const seenInvalid = new Set<string>();
  addresses.forEach((raw, i) => {
    const address = normalizedInput[i];
    if (isValidStellarAddress(address)) {
      if (!seenValid.has(address)) {
        seenValid.add(address);
        validAddresses.push(address);
      }
    } else if (!seenInvalid.has(raw)) {
      seenInvalid.add(raw);
      invalid.push(raw);
    }
  });
  const uniqueCount = validAddresses.length + invalid.length;

  const currentDenylistSet = new Set(currentDenylist.map(normalizeStellarAddress));
  if (reconcile) {
    // Denylist entries must be re-checked to learn whether they were cleared.
    for (const entry of currentDenylistSet) {
      if (isValidStellarAddress(entry) && !seenValid.has(entry)) {
        seenValid.add(entry);
        validAddresses.push(entry);
      }
    }
  }
  if (invalid.length > 0) {
    safeLogger.warn('sanctions-oracle: skipping malformed addresses', { count: invalid.length });
  }

  // On a resume run, drop anything a prior run already finished.
  const skipped: string[] = [];
  let pendingAddresses = validAddresses;
  if (resume && checkpoint) {
    pendingAddresses = [];
    const loaded = 'load' in checkpoint ? new Set(await checkpoint.load()) : undefined;
    for (const address of validAddresses) {
      const complete = loaded
        ? loaded.has(address)
        : await (checkpoint as SyncCheckpointStore).isComplete(address);
      if (complete) {
        skipped.push(address);
      } else {
        pendingAddresses.push(address);
      }
    }
    if (skipped.length > 0) {
      safeLogger.info('sanctions-oracle: resuming sync', {
        skipped: skipped.length,
        pending: pendingAddresses.length,
      });
    }
  }

  const inflightChecks = new Map<string, Promise<{ flagged: boolean; source: string }>>();
  const flagged: string[] = [];
  const flaggedWithSource: FlaggedAddressWithSource[] = [];
  const clearedWithSource: FlaggedAddressWithSource[] = [];
  const failed: string[] = [];
  const failedWithReasons: FailedAddress[] = [];
  let checked = 0;

  const getAddressResult = async (
    address: string,
  ): Promise<{ flagged: boolean; source: string }> => {
    if (cache) {
      return cache.getOrLoad(address, () => withRetry(() => provider.checkAddress(address), retry));
    }

    const cached = inflightChecks.get(address);
    if (cached) {
      return cached;
    }

    let resolve!: (value: { flagged: boolean; source: string }) => void;
    let reject!: (reason?: unknown) => void;
    const pending = new Promise<{ flagged: boolean; source: string }>((res, rej) => {
      resolve = res;
      reject = rej;
    });

    inflightChecks.set(address, pending);

    (async () => {
      try {
        const result = await withRetry(() => provider.checkAddress(address), retry);
        resolve(result);
      } catch (error) {
        reject(error);
      } finally {
        if (inflightChecks.get(address) === pending) {
          inflightChecks.delete(address);
        }
      }
    })();

    return pending;
  };

  await executeConcurrent(
    pendingAddresses,
    async (address) => {
      started.add(address);
      const start = Date.now();
      const span = tracer.startSpan('address_check');
      // address is omitted from spans by default (privacy / cardinality).
      span.setAttribute('address_check.index', normalizedInput.indexOf(address));
      try {
        const result = await getAddressResult(address);
        const durationMs = Date.now() - start;
        metrics.counter.inc('address_check', 'success');
        metrics.histogram.observe('address_check', durationMs);
        span.setAttribute('address_check.flagged', result.flagged);
        span.end('ok');
        if (result.flagged) {
          flagged.push(address);
          flaggedWithSource.push({ address, source: result.source });
        } else if (reconcile && currentDenylistSet.has(address)) {
          // Cleared by the provider but still on the denylist: it is only
          // checkpointed once the removal succeeds, so an interrupted removal
          // is retried on resume.
          clearedWithSource.push({ address, source: result.source });
        } else {
          // Clean address: nothing left to do for it, so it can be checkpointed
          // now. Flagged addresses are checkpointed only after a successful
          // write (below) so an interrupted write is retried on resume.
          await checkpoint?.markComplete(address);
        }
      } catch (err) {
        const durationMs = Date.now() - start;
        metrics.counter.inc('address_check', 'failure');
        metrics.histogram.observe('address_check', durationMs);
        span.end('error', err instanceof Error ? err : new Error(String(err)));
        failed.push(address);
        failedWithReasons.push({
          address,
          error: err instanceof Error ? err.message : String(err),
        });
      } finally {
        checked += 1;
        if (checked % progressInterval === 0) {
          progressLogger(`Progress: ${checked}/${uniqueCount} addresses checked`);
        }
      }
    },
    concurrency,
    pastDeadline,
  );
  const unprocessed = pendingAddresses.filter((address) => !started.has(address));
  const deadlineExceeded = unprocessed.length > 0;
  if (deadlineExceeded) {
    safeLogger.warn('sanctions-oracle: max duration elapsed; stopping new checks', {
      unprocessed: unprocessed.length,
    });
  }

  safeLogger.info('sanctions-oracle: screening complete', {
    checked: addresses.length,
    flagged: flagged.length,
  });

  const written: string[] = [];
  if (dryRun) {
    for (const { address } of flaggedWithSource) {
      if (currentDenylistSet.has(address)) {
        continue;
      }
      safeLogger.info('sanctions-oracle: [dry-run] would call add_to_denylist', { address });
    }
  } else {
    for (const { address, source } of flaggedWithSource) {
      if (currentDenylistSet.has(address)) {
        continue;
      }
      const start = Date.now();
      const span = tracer.startSpan('denylist_write');
      try {
        // Call writer with extended interface if available
        const writerExt = writer as DenylistWriter & {
          addToDenylistWithSource?: (
            address: string,
            source: string,
          ) => Promise<{ hash: string; auditLog?: AuditLogEntry }>;
        };
        let result: { hash: string; auditLog?: AuditLogEntry };
        if (writerExt.addToDenylistWithSource) {
          result = await writerExt.addToDenylistWithSource(address, source);
        } else {
          result = await writer.addToDenylist(address);
        }
        const durationMs = Date.now() - start;
        metrics.counter.inc('denylist_write', 'success');
        metrics.histogram.observe('denylist_write', durationMs);
        // transaction hash is set after success — it's a stable, non-PII identifier
        // Issue #598: checkpoint only after the denylist write has succeeded.
        span.setAttribute('denylist_write.tx_hash', result.hash);
        span.end('ok');
        written.push(address);
        await checkpoint?.markComplete(address);
        safeLogger.info('sanctions-oracle: address written to denylist', {
          address,
          hash: result.hash,
        });
      } catch (err) {
        const durationMs = Date.now() - start;
        metrics.counter.inc('denylist_write', 'failure');
        metrics.histogram.observe('denylist_write', durationMs);
        span.end('error', err instanceof Error ? err : new Error(String(err)));
        if (written.length > 0) {
          continue;
        }
        throw err;
      }
    }
  }

  const removed: string[] = [];
  const failedRemovals: FailedAddress[] = [];
  if (reconcile) {
    for (const { address, source } of clearedWithSource) {
      if (dryRun) {
        safeLogger.info('sanctions-oracle: [dry-run] would call remove_from_denylist', {
          address,
          source,
        });
        continue;
      }
      const span = tracer.startSpan('denylist_remove');
      try {
        let result: { hash: string; auditLog?: AuditLogEntry };
        if (writer.removeFromDenylistWithSource) {
          result = await writer.removeFromDenylistWithSource(address, source);
        } else {
          result = await writer.removeFromDenylist!(address);
        }
        span.setAttribute('denylist_remove.tx_hash', result.hash);
        span.end('ok');
        removed.push(address);
        await checkpoint?.markComplete(address);
        // Audit trail: every delisting is recorded with the clearing provider source.
        safeLogger.info('sanctions-oracle: address removed from denylist', {
          action: 'remove',
          address,
          source,
          hash: result.hash,
        });
      } catch (err) {
        span.end('error', err instanceof Error ? err : new Error(String(err)));
        failedRemovals.push({
          address,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  return {
    checked: started.size,
    flagged,
    written,
    failed,
    failedWithReasons,
    invalid,
    skipped,
    dryRun,
    ...(reconcile
      ? {
          removed,
          plannedRemovals: clearedWithSource.map(({ address, source }) => ({ address, source })),
          failedRemovals,
        }
      : {}),
    ...(maxDurationMs !== undefined ? { deadlineExceeded, unprocessed } : {}),
  };
}

export interface RpcDenylistWriterOptions {
  rpcUrl: string;
  networkPassphrase: string;
  contractId: string;
  /**
   * Oracle authority key. Either a `Keypair` or any {@link Signer}
   * (e.g. KMS/HSM-backed). Kept as `sourceKeypair` for backward compatibility.
   */
  sourceKeypair?: Keypair | Signer;
  /** Alias of `sourceKeypair` for Signer-based setups; takes precedence when both are set. */
  signer?: Keypair | Signer;
  /**
   * Optional separate fee-paying account. When set, every transaction is
   * wrapped in a FeeBumpTransaction whose fee is paid by this account.
   */
  feeSource?: Keypair | Signer;
  /**
   * Optional audit logger to record each denylist write for compliance purposes.
   * Called with address, timestamp, source, and resulting transaction hash.
   */
  auditLogger?: AuditLogger;
  /**
   * Optional maximum number of retry attempts for sendTransaction.
   * Defaults to 3.
   */
  maxRetries?: number;
  /**
   * Optional backoff options for retry delays.
   */
  backoffOptions?: BackoffOptions;
  /**
   * Optional logger used to record an audit-logging failure without failing
   * the write it accompanies. Defaults to a no-op logger.
   */
  logger?: Logger;
}

// Kept behind the DenylistWriter interface (rather than called directly
// from syncSanctionsToDenylist) so tests can inject a fake writer instead
// of touching a live RPC endpoint.
export function createRpcDenylistWriter(options: RpcDenylistWriterOptions): DenylistWriter & {
  addToDenylistWithSource?: (
    address: string,
    source: string,
  ) => Promise<{ hash: string; auditLog?: AuditLogEntry }>;
  removeFromDenylist: (address: string) => Promise<{ hash: string }>;
  removeFromDenylistWithSource: (
    address: string,
    source: string,
  ) => Promise<{ hash: string; auditLog?: AuditLogEntry }>;
} {
  const {
    rpcUrl,
    networkPassphrase,
    contractId,
    sourceKeypair,
    signer: signerOption,
    feeSource: feeSourceOption,
    auditLogger,
    maxRetries = 3,
    backoffOptions,
    logger = noopLogger,
  } = options;
  const authority = signerOption ?? sourceKeypair;
  if (!authority) {
    throw new Error('sanctions-oracle: createRpcDenylistWriter requires a signer or sourceKeypair');
  }
  const signer = toSigner(authority);
  const feeSigner = feeSourceOption ? toSigner(feeSourceOption) : undefined;
  const server = new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });
  const contract = new Contract(contractId);

  // Shared by both public methods below so the retry/backoff behavior around
  // sendTransaction can't drift between the audited and non-audited paths.
  async function buildPrepareSignAndSend(
    address: string,
    method: 'add_to_denylist' | 'remove_from_denylist' = 'add_to_denylist',
  ): Promise<{ hash: string }> {
    const account = await server.getAccount(signer.publicKey());

    const tx = new TransactionBuilder(account, {
      fee: BASE_FEE,
      networkPassphrase,
    })
      .addOperation(contract.call(method, nativeToScVal(address, { type: 'address' })))
      .setTimeout(30)
      .build();

    let prepared;
    try {
      prepared = await server.prepareTransaction(tx);
    } catch (error) {
      const err = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to prepare transaction (simulation error): ${err}`);
    }

    await signTransaction(prepared, signer);

    let envelope: Transaction | FeeBumpTransaction = prepared;
    if (feeSigner) {
      envelope = TransactionBuilder.buildFeeBumpTransaction(
        feeSigner.publicKey(),
        BASE_FEE,
        prepared,
        networkPassphrase,
      );
      await signTransaction(envelope, feeSigner);
    }

    let lastError;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const sendResult = await server.sendTransaction(envelope);
        return { hash: sendResult.hash };
      } catch (error) {
        lastError = error;
        if (attempt < maxRetries - 1) {
          const delayMs = computeBackoffDelayMs(attempt, backoffOptions);
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
      }
    }

    const err = lastError instanceof Error ? lastError.message : String(lastError);
    throw new Error(`Failed to send transaction after ${maxRetries} attempts: ${err}`);
  }

  // Shared by the add and remove audited paths so audit-failure handling
  // can't drift between them.
  async function writeAuditEntry(auditEntry: AuditLogEntry): Promise<void> {
    const { address, txHash: hash } = auditEntry;
    if (auditLogger) {
      try {
        await auditLogger(auditEntry);
      } catch (error) {
        // The on-chain write above already succeeded — an audit-logging
        // failure must not fail this address's write or propagate up
        // through syncSanctionsToDenylist's write loop.
        logger.error?.('sanctions-oracle: audit logger failed after successful denylist write', {
          address,
          txHash: hash,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  return {
    async addToDenylist(address: string): Promise<{ hash: string }> {
      return buildPrepareSignAndSend(address);
    },
    async addToDenylistWithSource(
      address: string,
      source: string,
    ): Promise<{ hash: string; auditLog?: AuditLogEntry }> {
      const { hash } = await buildPrepareSignAndSend(address);

      const auditEntry: AuditLogEntry = {
        address,
        timestamp: new Date().toISOString(),
        source,
        txHash: hash,
      };
      await writeAuditEntry(auditEntry);

      return { hash, auditLog: auditEntry };
    },
    async removeFromDenylist(address: string): Promise<{ hash: string }> {
      return buildPrepareSignAndSend(address, 'remove_from_denylist');
    },
    async removeFromDenylistWithSource(
      address: string,
      source: string,
    ): Promise<{ hash: string; auditLog?: AuditLogEntry }> {
      const { hash } = await buildPrepareSignAndSend(address, 'remove_from_denylist');

      const auditEntry: AuditLogEntry = {
        address,
        action: 'remove',
        timestamp: new Date().toISOString(),
        source,
        txHash: hash,
      };
      await writeAuditEntry(auditEntry);

      return { hash, auditLog: auditEntry };
    },
  };
}

export interface CliArgs {
  addressesPath?: string;
  dryRun: boolean;
  contractId?: string;
  rpcUrl?: string;
  networkPassphrase?: string;
  secretKey?: string;
  help?: boolean;
  /** Path to a CSV file of flagged addresses, used to build a CsvSanctionsProvider. */
  csvPath?: string;
  /** Path to a module exporting a SanctionsProvider-compatible default export. */
  providerModulePath?: string;
  /** Wrap the selected provider with RateLimitedSanctionsProvider's backoff/concurrency protection. */
  rateLimit?: boolean;
  /** Opt in to delisting: remove denylist addresses the provider has cleared. Requires `denylistSnapshotPath`. */
  reconcile?: boolean;
  /** Path to a JSON array of the addresses currently on the denylist (the last snapshot). */
  denylistSnapshotPath?: string;
  /** Print only the JSON SyncResult on stdout; route all logs to stderr. */
  json?: boolean;
  /** Path to an append-only JSONL file that records every denylist write. */
  auditLogPath?: string;
  /** Path to a checkpoint file; addresses completed by a prior run are skipped. */
  checkpointPath?: string;
}

/** Logger that writes every level to stderr, keeping stdout clean for `--json`. */
const stderrLogger: Logger = {
  debug: (...args: unknown[]) => console.error(...args),
  info: (...args: unknown[]) => console.error(...args),
  warn: (...args: unknown[]) => console.error(...args),
  error: (...args: unknown[]) => console.error(...args),
};

/**
 * Returns a copy of `args` safe for logging, with `secretKey` masked.
 * Use this instead of logging the raw `CliArgs` object.
 */
export function toSafeLogString(args: CliArgs): string {
  return JSON.stringify({ ...args, secretKey: args.secretKey ? '[REDACTED]' : undefined });
}

export function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { dryRun: false };
  const readValue = (flag: string, index: number): string => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('-')) {
      throw new Error(`Missing value for ${flag}`);
    }
    return value;
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--addresses':
        args.addressesPath = readValue(arg, i);
        i += 1;
        break;
      case '--dry-run':
        args.dryRun = true;
        break;
      case '--contract-id':
        args.contractId = readValue(arg, i);
        i += 1;
        break;
      case '--rpc-url':
        args.rpcUrl = readValue(arg, i);
        i += 1;
        break;
      case '--network-passphrase':
        args.networkPassphrase = readValue(arg, i);
        i += 1;
        break;
      case '--secret-key':
        args.secretKey = readValue(arg, i);
        i += 1;
        break;
      case '--csv':
        args.csvPath = readValue(arg, i);
        i += 1;
        break;
      case '--provider-module':
        args.providerModulePath = readValue(arg, i);
        i += 1;
        break;
      case '--rate-limit':
        args.rateLimit = true;
        break;
      case '--reconcile':
        args.reconcile = true;
        break;
      case '--max-duration': {
        const ms = Number(readValue(arg, i));
        if (!Number.isFinite(ms) || ms <= 0) {
          throw new Error('--max-duration must be a positive number of milliseconds');
        }
        args.maxDurationMs = ms;
        i += 1;
        break;
      }
      case '--denylist-snapshot':
        args.denylistSnapshotPath = readValue(arg, i);
        i += 1;
        break;
      case '--json':
        args.json = true;
        break;
      case '--audit-log':
        args.auditLogPath = readValue(arg, i);
        i += 1;
        break;
      case '--checkpoint':
        args.checkpointPath = readValue(arg, i);
        i += 1;
        break;
      case '--help':
      case '-h':
        args.help = true;
        break;
      default:
        break;
    }
  }
  return args;
}

function printHelp(): void {
  // CLI-only: help text is written straight to stdout by convention, not routed
  // through an injectable Logger.
  // eslint-disable-next-line no-console
  console.log(`
sanctions-oracle sync - Synchronize sanctions data to a Soroban denylist

USAGE:
  sanctions-oracle sync [OPTIONS]

OPTIONS:
  --addresses <path>          Path to JSON file containing array of addresses to check
  --contract-id <id>          Soroban contract ID (required for live sync)
  --rpc-url <url>             Soroban RPC endpoint URL (required for live sync)
  --network-passphrase <str>  Network passphrase (required for live sync)
  --secret-key <key>          Source account secret key (required for live sync unless
                               SANCTIONS_ORACLE_SECRET_KEY is set; discouraged outside
                               local testing since it is visible in shell history/process lists)
  --csv <path>                Use a CsvSanctionsProvider backed by the given CSV file
  --provider-module <path>    Dynamically import a module whose default export is a
                               SanctionsProvider to use instead of the mock/CSV provider
  --rate-limit                Wrap the selected provider with RateLimitedSanctionsProvider
  --reconcile                 Opt in to delisting: remove addresses from the denylist once the
                               provider no longer flags them (requires --denylist-snapshot);
                               combine with --dry-run to preview the planned removals
  --max-duration <ms>         Hard deadline for the run. When it elapses no new checks start,
                               in-flight checks finish, results are saved and the process
                               exits with code 3 (EXIT_CODE_DEADLINE_EXCEEDED)
  --denylist-snapshot <path>  Path to JSON file containing an array of the addresses currently
                               on the denylist
  --dry-run                   Preview output without writing to the contract
  --json                      Print only the JSON SyncResult on stdout; logs go to stderr
  --audit-log <path>          Append one JSON line per denylist write to <path>
  --checkpoint <path>         Persist completed addresses to <path> and skip them on re-run
  --help, -h                  Show this help message

ENVIRONMENT:
  SANCTIONS_ORACLE_SECRET_KEY  Source account secret key (preferred over --secret-key)
  SANCTIONS_ORACLE_FEE_SOURCE_SECRET_KEY  Optional separate fee account; when set every
                               transaction is wrapped in a fee-bump paid by this account

EXAMPLES:
  # Dry-run mode: check addresses without writing
  sanctions-oracle sync --addresses addresses.json --dry-run

  # Live mode: sync flagged addresses to contract (preferred, via env var)
  SANCTIONS_ORACLE_SECRET_KEY=SBXXXX sanctions-oracle sync \\
    --addresses addresses.json \\
    --contract-id CXXXX \\
    --rpc-url https://soroban-testnet.stellar.org \\
    --network-passphrase "Test SDF Network ; September 2015"
  `);
}

export async function runCli(argv?: string[]): Promise<void> {
  // The CLI entrypoint uses consoleLogger so dry-run output and errors are
  // visible by default; programmatic callers should inject their own logger.
  const processArgv = argv ?? process.argv.slice(2);
  const args = parseArgs(processArgv);
  // --json reserves stdout for the single JSON SyncResult.
  const logger = args.json ? stderrLogger : consoleLogger;

  if (args.help) {
    printHelp();
    return;
  }

  if (!args.addressesPath) {
    logger.error?.('sanctions-oracle: Missing required flag: --addresses <path-to-json-array>');
    process.exitCode = 1;
    return;
  }

  let addresses: string[];
  try {
    const parsed = JSON.parse(fs.readFileSync(args.addressesPath, 'utf8'));
    if (!Array.isArray(parsed)) {
      throw new Error('Addresses file must contain a JSON array');
    }
    if (!parsed.every((item) => typeof item === 'string')) {
      throw new Error('All entries in the addresses array must be strings');
    }
    const emptyStrings = parsed.filter((addr) => addr === '');
    if (emptyStrings.length > 0) {
      throw new Error(`Addresses file contains ${emptyStrings.length} empty string entries`);
    }
    const uniqueAddresses = Array.from(new Set(parsed.map(normalizeStellarAddress)));
    const duplicateCount = parsed.length - uniqueAddresses.length;
    if (duplicateCount > 0) {
      logger.info(`sanctions-oracle: deduplicating ${duplicateCount} duplicate addresses`);
    }
    addresses = parsed.map(normalizeStellarAddress);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(
      `sanctions-oracle: Failed to load addresses from ${args.addressesPath}: ${message}`,
    );
    process.exitCode = 1;
    return;
  }
  if (args.reconcile && !args.denylistSnapshotPath) {
    logger.error?.(
      'sanctions-oracle: --reconcile requires --denylist-snapshot <path-to-json-array> listing the current denylist',
    );
    process.exitCode = 1;
    return;
  }

  let currentDenylist: string[] | undefined;
  if (args.denylistSnapshotPath) {
    try {
      const parsed = JSON.parse(fs.readFileSync(args.denylistSnapshotPath, 'utf8'));
      if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === 'string')) {
        throw new Error('Denylist snapshot must be a JSON array of strings');
      }
      currentDenylist = parsed;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error(
        `sanctions-oracle: Failed to load denylist snapshot from ${args.denylistSnapshotPath}: ${message}`,
      );
      process.exitCode = 1;
      return;
    }
  }

  let provider: SanctionsProvider;
  if (args.providerModulePath) {
    try {
      const imported = await import(args.providerModulePath);
      provider = (imported.default ?? imported) as SanctionsProvider;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error(`Failed to load provider module ${args.providerModulePath}: ${message}`);
      process.exitCode = 1;
      return;
    }
  } else if (args.csvPath) {
    provider = new CsvSanctionsProvider(args.csvPath);
  } else {
    provider = new MockSanctionsProvider();
  }

  if (args.rateLimit) {
    provider = new RateLimitedSanctionsProvider(provider);
  }

  if (args.dryRun) {
    const result = await syncSanctionsToDenylist({
      provider,
      addresses,
      writer: {
        async addToDenylist(): Promise<{ hash: string }> {
          throw new Error('addToDenylist should not be called in dry-run mode');
        },
      },
      dryRun: true,
      logger,
      currentDenylist,
      reconcile: args.reconcile,
      maxDurationMs: args.maxDurationMs,
    });
    if (!args.json) logger.info('sanctions-oracle: dry-run result', result);
    // CLI-only: the machine-readable result is written to stdout so it can be
    // piped/redirected independently of the human-readable logger stream.
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(result, null, 2));
    if (result.deadlineExceeded) process.exitCode = EXIT_CODE_DEADLINE_EXCEEDED;
    return;
  }

  // Prefer the environment variable over --secret-key: CLI args are visible
  // in shell history and process listings (e.g. `ps`), which the flag alone
  // is vulnerable to.
  const secretKey = process.env.SANCTIONS_ORACLE_SECRET_KEY ?? args.secretKey;

  if (!args.contractId || !args.rpcUrl || !args.networkPassphrase || !secretKey) {
    logger.error?.(
      'sanctions-oracle: Missing required flags for a live sync. Required: --contract-id, --rpc-url, --network-passphrase, and SANCTIONS_ORACLE_SECRET_KEY (env, preferred) or --secret-key (or pass --dry-run).',
    );
    process.exitCode = 1;
    return;
  }

  // Checkpoints only apply to live syncs; a dry run never marks addresses done.
  const checkpoint = args.checkpointPath
    ? new FileCheckpointStore(args.checkpointPath, logger)
    : undefined;

  const writer = createRpcDenylistWriter({
    rpcUrl: args.rpcUrl,
    networkPassphrase: args.networkPassphrase,
    contractId: args.contractId,
    sourceKeypair: Keypair.fromSecret(secretKey),
    // --audit-log persists every write; otherwise delistings are logged with
    // the clearing provider's source.
    ...(args.auditLogPath
      ? { auditLogger: createJsonlAuditLogger(args.auditLogPath), logger }
      : args.reconcile
        ? { auditLogger: (entry: AuditLogEntry) => logger.info('sanctions-oracle: audit', entry), logger }
        : {}),
  });

  const result = await syncSanctionsToDenylist({
    provider,
    addresses,
    writer,
    dryRun: false,
    logger,
    currentDenylist,
    reconcile: args.reconcile,
    checkpoint,
    resume: Boolean(checkpoint),
  });
  // CLI-only: machine-readable result to stdout (see dry-run branch above).
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(result, null, 2));
  if (result.deadlineExceeded) process.exitCode = EXIT_CODE_DEADLINE_EXCEEDED;
}

if (require.main === module) {
  runCli().catch((err) => {
    // CLI-only: last-resort crash handler for the binary entrypoint; no logger
    // is in scope here.
    // eslint-disable-next-line no-console
    console.error('sanctions-oracle:', err);
    process.exitCode = 1;
  });
}
