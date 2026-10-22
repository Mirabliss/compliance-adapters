/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { createHmac } from 'node:crypto';
import { computeBackoffDelayMs } from '@compliance-adapters/backoff';
import type { RawContractEvent } from './eventSource';
import { type AnyMetricsRegistry, NoopMetricsRegistry } from './metrics';
import { type AnyTracer, NoopTracer, type TracingContext } from './tracing';

export interface WebhookSender {
  send(event: RawContractEvent): Promise<void>;
}

/**
 * Thrown when the webhook endpoint responds with a non-OK HTTP status.
 * Carries the status code so callers (and the retry loop below) can tell a
 * permanent client error (4xx) apart from a transient server error (5xx).
 *
 * @example
 * ```ts
 * import { HttpWebhookSender, WebhookHttpError } from 'horizon-listener';
 *
 * try {
 *   await sender.send(event);
 * } catch (err) {
 *   if (err instanceof WebhookHttpError) {
 *     console.error('webhook returned HTTP', err.status);
 *   }
 * }
 * ```
 */
export class WebhookHttpError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = 'WebhookHttpError';
  }
}

export interface HttpWebhookSenderOptions {
  url: string;
  /**
   * Shared secret used to sign outbound requests. When set, every request
   * carries an `X-Timestamp` header (Unix seconds) and an `X-Signature`
   * header (`sha256=<hex hmac>`) computed over `<timestamp>.<raw body>` so
   * receivers can verify the request came from this sender *and* reject
   * stale/replayed deliveries by enforcing a freshness window on the
   * timestamp. See horizon-listener/README.md for the verification recipe.
   */
  signingSecret?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /**
   * Maximum retry attempts (with exponential backoff) for transient
   * failures: 5xx responses and network errors. A 4xx response is treated
   * as a permanent client error (bad config, auth, etc.) and is never
   * retried, regardless of this setting. Defaults to 3.
   */
  maxRetries?: number;
  /**
   * Optional metrics registry.  Pass a `MetricsRegistry` instance to record
   * per-call counters and latency histograms for the `webhook` phase.
   * Defaults to a no-op registry — zero overhead when omitted.
   */
  metrics?: AnyMetricsRegistry;
  /**
   * Optional tracer for OpenTelemetry-compatible distributed tracing.
   * When omitted, a no-op tracer is used — zero overhead and no exports.
   *
   * Pass a parent `TracingContext` alongside the tracer to nest webhook spans
   * inside an existing trace tree (e.g. a parent `event_relay` span).
   */
  tracer?: AnyTracer;
  /** Parent context for outbound webhook spans. */
  parentContext?: TracingContext;
  /**
   * Static headers sent with every request (e.g. an API-gateway key or tenant
   * id). Reserved headers (`Content-Type`, `X-Signature`, `X-Timestamp`,
   * `traceparent`) always win and cannot be overridden.
   */
  headers?: Record<string, string>;
  /**
   * Client certificate material for mutual TLS. When set, an undici `Agent`
   * is created and used as the fetch dispatcher. Requires the `undici`
   * package to be installed. Ignored when `dispatcher` is passed.
   */
  tls?: { cert?: string | Buffer; key?: string | Buffer; ca?: string | Buffer | Array<string | Buffer> };
  /** Custom undici dispatcher passed through to fetch (e.g. a pre-configured mTLS Agent). */
  dispatcher?: unknown;
}

/** Maximum number of response-body characters included in error messages. */
export const MAX_ERROR_BODY_CHARS = 2048;

const RESERVED_HEADERS = new Set(['content-type', 'x-signature', 'x-timestamp', 'traceparent']);

// Reads at most MAX_ERROR_BODY_CHARS of the body, strips control characters
// and appends a marker when truncated, so large HTML error pages don't flood
// logs or leak data.
async function readErrorBody(response: Response): Promise<string> {
  let text: string;
  try {
    text = await response.text();
  } catch {
    return '';
  }
  // eslint-disable-next-line no-control-regex
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ').trim();
  return clean.length > MAX_ERROR_BODY_CHARS
    ? `${clean.slice(0, MAX_ERROR_BODY_CHARS)}…[truncated ${clean.length - MAX_ERROR_BODY_CHARS} chars]`
    : clean;
}

function createTlsDispatcher(tls: NonNullable<HttpWebhookSenderOptions['tls']>): unknown {
  let undici: { Agent: new (opts: unknown) => unknown };
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    undici = require('undici');
  } catch {
    throw new Error(
      'horizon-listener: HttpWebhookSender `tls` option requires the "undici" package; install it or pass a `dispatcher`',
    );
  }
  return new undici.Agent({ connect: { cert: tls.cert, key: tls.key, ca: tls.ca } });
}

export class HttpWebhookSender implements WebhookSender {
  private readonly url: string;
  private readonly signingSecret?: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number | undefined;
  private readonly maxRetries: number;
  private readonly metrics: AnyMetricsRegistry;
  private readonly tracer: AnyTracer;
  private readonly parentContext: TracingContext | undefined;
  private readonly customHeaders: Record<string, string>;
  private readonly dispatcher: unknown;

  constructor(options: HttpWebhookSenderOptions) {
    // Validate URL is syntactically valid and has a protocol (http/https)
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(options.url);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      throw new Error(
        `horizon-listener: HttpWebhookSender invalid URL "${options.url}" (${reason})`,
      );
    }

    // Ensure URL has a protocol (http or https) to catch typos like "localhost:3000"
    if (!parsedUrl.protocol.startsWith('http')) {
      throw new Error(
        `horizon-listener: HttpWebhookSender invalid URL "${options.url}" (must start with http:// or https://)`,
      );
    }

    this.url = options.url;
    this.signingSecret = options.signingSecret;
    // Node 20+ ships a global fetch; fetchImpl is injectable so tests never
    // make a real network call.
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs;
    this.maxRetries = options.maxRetries ?? 3;
    this.metrics = options.metrics ?? new NoopMetricsRegistry();
    this.tracer = options.tracer ?? new NoopTracer();
    this.parentContext = options.parentContext;
    this.customHeaders = Object.fromEntries(
      Object.entries(options.headers ?? {}).filter(([k]) => !RESERVED_HEADERS.has(k.toLowerCase())),
    );
    this.dispatcher = options.dispatcher ?? (options.tls ? createTlsDispatcher(options.tls) : undefined);
  }

  /**
   * Sends an event to the configured webhook URL.
   * @throws {Error} When the HTTP response is not OK (status >= 400).
   * Consumers should handle this error with retry logic or fallback behavior.
   */
  async send(event: RawContractEvent): Promise<void> {
    const body = JSON.stringify({ event });
    const headers: Record<string, string> = {
      ...this.customHeaders,
      'Content-Type': 'application/json',
    };

    if (this.signingSecret) {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      headers['X-Timestamp'] = timestamp;
      headers['X-Signature'] = `sha256=${this.sign(timestamp, body)}`;
    }

    // The span covers the entire logical delivery (including retries), so it
    // is started once here and ended exactly once below on final success or
    // final failure — not per attempt.
    const span = this.tracer.startSpan('webhook', this.parentContext);
    span.setAttribute('webhook.url', this.url);
    // event.id is a stable, low-cardinality correlation identifier — safe to attach
    span.setAttribute('event.id', event.id);

    // Inject traceparent into outbound request headers for downstream correlation
    const traceparent = span.traceId
      ? this.tracer.injectContext({ traceId: span.traceId, spanId: span.spanId })
      : undefined;
    if (traceparent) {
      headers['traceparent'] = traceparent;
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        const delayMs = computeBackoffDelayMs(attempt - 1);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }

      const start = Date.now();
      try {
        const controller = this.timeoutMs ? new AbortController() : undefined;
        let timeoutHandle: NodeJS.Timeout | undefined;

        try {
          if (controller && this.timeoutMs) {
            timeoutHandle = setTimeout(() => controller.abort(), this.timeoutMs);
          }

          const response = await this.fetchImpl(this.url, {
            method: 'POST',
            headers,
            body,
            signal: controller?.signal,
            ...(this.dispatcher ? { dispatcher: this.dispatcher } : {}),
          } as RequestInit);

          const durationMs = Date.now() - start;

          if (!response.ok) {
            const errorBody = await readErrorBody(response);
            throw new WebhookHttpError(
              `horizon-listener: webhook POST to ${this.url} failed with status ${response.status}` +
                (errorBody ? `: ${errorBody}` : ''),
              response.status,
            );
          }

          this.metrics.counter.inc('webhook', 'success');
          this.metrics.histogram.observe('webhook', durationMs);
          span.setAttribute('http.status_code', response.status);
          span.end('ok');
          return;
        } finally {
          if (timeoutHandle) {
            clearTimeout(timeoutHandle);
          }
        }
      } catch (error) {
        const httpError = error instanceof WebhookHttpError ? error : undefined;
        const durationMs = Date.now() - start;
        this.metrics.counter.inc('webhook', 'failure');
        this.metrics.histogram.observe('webhook', durationMs);
        lastError = error instanceof Error ? error : new Error(String(error));

        // 4xx responses are permanent client errors (bad config, auth, etc.)
        // that will never succeed on retry, so fail fast instead of burning
        // the retry budget. 5xx responses and network errors are treated as
        // transient and keep retrying up to maxRetries.
        const isPermanentClientError =
          httpError !== undefined && httpError.status >= 400 && httpError.status < 500;
        if (isPermanentClientError || attempt === this.maxRetries) {
          span.end('error', lastError);
          throw lastError;
        }
      }
    }
  }

  private sign(timestamp: string, body: string): string {
    return createHmac('sha256', this.signingSecret!).update(`${timestamp}.${body}`).digest('hex');
  }
}
