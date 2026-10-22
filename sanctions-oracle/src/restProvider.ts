/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * @file restProvider.ts
 *
 * Reference REST-backed implementation of {@link SanctionsProvider}.
 *
 * On every `checkAddress` call it issues a single GET request to
 * `<apiBaseUrl>/check?address=<address>` and maps the JSON response to the
 * `{ flagged, source }` shape the sync engine expects.
 *
 * ## Usage
 *
 * ```ts
 * import { RestSanctionsProvider, syncSanctionsToDenylist } from 'sanctions-oracle';
 *
 * const provider = new RestSanctionsProvider({
 *   apiBaseUrl: 'https://api.watchlist-provider.com',
 *   apiKey: process.env.WATCHLIST_API_KEY!,
 * });
 *
 * await syncSanctionsToDenylist({ provider, addresses, writer });
 * ```
 *
 * **Fail-open vs fail-closed:** The catch block re-throws so the caller
 * (or the retry wrapper inside the sync engine) decides whether to fail
 * open (skip the address) or fail closed (treat it as flagged).
 * Override this behaviour in a subclass or wrapper if your compliance
 * policy requires a different default.
 */

import type { SanctionsProvider } from './SanctionsProvider';
import { normalizeStellarAddress } from '@compliance-adapters/shared';
import { NoopTracer, type AnyTracer, type TracingContext } from './tracing';

/** Shape returned by the hypothetical watchlist REST API. */
interface SanctionsApiResponse {
  is_flagged: boolean;
  risk_level?: string;
  lists: string[];
}

export interface RestSanctionsProviderOptions {
  /** Base URL of the watchlist REST API, e.g. https://api.watchlist-provider.com */
  apiBaseUrl: string;
  /** API key passed as a Bearer token in the Authorization header. */
  apiKey: string;
  /**
   * Request timeout in milliseconds.  Implemented via AbortController so it
   * works with the standard Fetch API.  Defaults to 5 000 ms.
   */
  timeoutMs?: number;
  /**
   * Injectable fetch implementation.  Defaults to the global `fetch`.
   * Override in tests to avoid real network I/O.
   */
  fetchImpl?: typeof fetch;
  /** Optional tracer; spans named `watchlist_check` when provided. */
  tracer?: AnyTracer;
  /** Parent context for the outbound check span. */
  parentContext?: TracingContext;
  /** When `false`, no `traceparent` header is sent. Defaults to `true`. */
  propagateTraceContext?: boolean;
}

/**
 * REST-backed implementation of {@link SanctionsProvider}.
 *
 * Calls a configurable HTTP endpoint per address and maps the JSON
 * response to the `{ flagged, source }` shape the sync engine expects.
 */
export class RestSanctionsProvider implements SanctionsProvider {
  private readonly apiBaseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly tracer: AnyTracer;
  private readonly parentContext: TracingContext | undefined;
  private readonly propagateTraceContext: boolean;

  constructor(options: RestSanctionsProviderOptions) {
    this.apiBaseUrl = options.apiBaseUrl.replace(/\/$/, ''); // strip trailing slash
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 5_000;
    // Node 20+ ships a global fetch; fetchImpl is injectable so tests never
    // make a real network call.
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.tracer = options.tracer ?? new NoopTracer();
    this.parentContext = options.parentContext;
    this.propagateTraceContext = options.propagateTraceContext !== false;
  }

  async checkAddress(rawAddress: string): Promise<{ flagged: boolean; source: string }> {
    // Query the provider with the canonical spelling so padded / lowercase
    // input cannot miss a match.
    const address = normalizeStellarAddress(rawAddress);
    const url = `${this.apiBaseUrl}/check?address=${encodeURIComponent(address)}`;
    const span = this.tracer.startSpan('watchlist_check', this.parentContext);
    span.setAttribute('address', address.slice(0, 8));

    const headers: Record<string, string> = { Authorization: `Bearer ${this.apiKey}` };
    // Inject W3C traceparent so the watchlist API can continue the trace.
    if (this.propagateTraceContext && span.traceId) {
      headers['traceparent'] = this.tracer.injectContext({
        traceId: span.traceId,
        spanId: span.spanId,
      });
    }

    // AbortController-based timeout — the `timeout` property on RequestInit is
    // not part of the Fetch specification and is silently ignored by Node's
    // built-in fetch implementation.
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        headers,
        signal: controller.signal,
      });
    } catch (error) {
      span.end('error', error instanceof Error ? error : new Error(String(error)));
      const isTimeout =
        error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError');
      const message = isTimeout
        ? `Watchlist API request timed out after ${this.timeoutMs} ms (address: ${address})`
        : `Watchlist API request failed for address ${address}: ${String(error)}`;
      throw new Error(message);
    } finally {
      clearTimeout(timeoutHandle);
    }

    if (!response.ok) {
      span.end('error', new Error(`HTTP ${response.status}`));
      throw new Error(
        `Watchlist API returned HTTP ${response.status} for address ${address}`,
      );
    }

    const data = (await response.json()) as SanctionsApiResponse;
    span.end('ok');

    return {
      flagged: data.is_flagged,
      source: data.lists.join(',') || 'external-watchlist-api',
    };
  }
}
