/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * @file chainalysis.ts
 *
 * Example {@link SanctionsProvider} backed by the free Chainalysis sanctions
 * screening API (https://public.chainalysis.com/api/v1/address/<address>).
 *
 * The API returns `{ identifications: [...] }`; a non-empty array means the
 * address appears on a sanctions list. The API key is read from the
 * `CHAINALYSIS_API_KEY` environment variable and sent as `X-API-Key`.
 *
 * ## Usage
 *
 * ```ts
 * import { syncSanctionsToDenylist } from 'sanctions-oracle';
 * import { createChainalysisProvider } from './examples/providers/chainalysis';
 *
 * const provider = createChainalysisProvider(); // rate-limited by default
 * await syncSanctionsToDenylist({ provider, addresses, writer });
 * ```
 *
 * Or from the CLI, compile this file and pass it as a provider module:
 * `sanctions-sync --provider-module ./chainalysis.js --addresses a.json --dry-run`
 */

import {
  RateLimitedSanctionsProvider,
  type RateLimitOptions,
  type SanctionsProvider,
} from 'sanctions-oracle';

const DEFAULT_BASE_URL = 'https://public.chainalysis.com/api/v1/address';

/** Shape returned by the Chainalysis sanctions screening API. */
interface ChainalysisResponse {
  identifications: Array<{
    category: string;
    name?: string;
    description?: string;
    url?: string;
  }>;
}

export interface ChainalysisProviderOptions {
  /** API key; defaults to `process.env.CHAINALYSIS_API_KEY`. */
  apiKey?: string;
  /** Override the API base URL (e.g. for a proxy). */
  baseUrl?: string;
  /** Request timeout in milliseconds. Defaults to 5 000 ms. */
  timeoutMs?: number;
  /** Injectable fetch implementation, so tests never hit the network. */
  fetchImpl?: typeof fetch;
}

/** {@link SanctionsProvider} that screens addresses via the Chainalysis API. */
export class ChainalysisSanctionsProvider implements SanctionsProvider {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ChainalysisProviderOptions = {}) {
    const apiKey = options.apiKey ?? process.env.CHAINALYSIS_API_KEY;
    if (!apiKey) {
      throw new Error('ChainalysisSanctionsProvider: set CHAINALYSIS_API_KEY or pass apiKey');
    }
    this.apiKey = apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? 5_000;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async checkAddress(address: string): Promise<{ flagged: boolean; source: string }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}/${encodeURIComponent(address)}`, {
        headers: { 'X-API-Key': this.apiKey, Accept: 'application/json' },
        signal: controller.signal,
      });
      if (!response.ok) {
        // Includes 429; RateLimitedSanctionsProvider backs off and retries.
        const error = new Error(`Chainalysis API responded with HTTP ${response.status}`);
        (error as Error & { status?: number }).status = response.status;
        throw error;
      }
      const body = (await response.json()) as ChainalysisResponse;
      const identifications = Array.isArray(body.identifications) ? body.identifications : [];
      const flagged = identifications.length > 0;
      const names = identifications.map((id) => id.name ?? id.category).filter(Boolean);
      return {
        flagged,
        source: flagged ? `chainalysis:${names.join(',')}` : 'chainalysis',
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Builds a Chainalysis provider wrapped in {@link RateLimitedSanctionsProvider}
 * so 429s are retried with backoff and concurrency stays bounded.
 */
export function createChainalysisProvider(
  options: ChainalysisProviderOptions = {},
  rateLimit: RateLimitOptions = {},
): SanctionsProvider {
  return new RateLimitedSanctionsProvider(new ChainalysisSanctionsProvider(options), rateLimit);
}

let defaultProvider: SanctionsProvider | undefined;

/**
 * Default export for `--provider-module`. Built lazily on first use so merely
 * importing this module doesn't require `CHAINALYSIS_API_KEY`.
 */
const lazyProvider: SanctionsProvider = {
  checkAddress(address) {
    defaultProvider ??= createChainalysisProvider();
    return defaultProvider.checkAddress(address);
  },
};

export default lazyProvider;
