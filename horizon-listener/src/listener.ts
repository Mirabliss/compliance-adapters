/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { CursorOutOfRangeError, type EventSource, type RawContractEvent } from './eventSource';
import { computeBackoffDelayMs, type BackoffOptions } from '@compliance-adapters/backoff';
import { type AnyMetricsRegistry, NoopMetricsRegistry } from './metrics';
import { type AnyTracer, NoopTracer, type TracingContext } from './tracing';
import { type Logger, consoleLogger } from '@compliance-adapters/logger';

// Re-export so existing consumers that imported Logger from this module
// continue to compile without changes.
export type { Logger };

export interface HorizonListenerOptions {
  eventSource: EventSource;
  onEvent: (event: RawContractEvent) => Promise<void> | void;
  onEventFailure?: (event: RawContractEvent, error: unknown) => void | Promise<void>;
  /** Retry failed event handlers. `maxRetries` is the maximum number of attempts. */
  eventRetry?: { maxRetries?: number; jitter?: boolean; baseMs?: number; maxMs?: number };
  pollIntervalMs?: number;
  /**
   * Maximum number of consecutive polling failures before giving up.
   * When a poll fails, a counter increments; it resets to 0 on success.
   * Once `attempts >= maxRetries`, the listener throws with an error.
   *
   * @default 10
   *
   * **Important:** `maxRetries: 0` means "fail immediately on the first error"
   * (since 1 >= 0), not "disable the retry limit" or "retry infinitely".
   * To disable the retry ceiling entirely, use `maxRetries: Infinity`.
   *
   * Example: with `maxRetries: 3`, the listener allows up to 3 consecutive
   * failed polls (attempts 1, 2, 3) before throwing; the error message
   * will say "giving up after 3 consecutive failed polls".
   */
  maxRetries?: number;
  logger?: Logger;
  // Injectable so tests can drive time with Jest fake timers instead of waiting
  // on the real wall clock.
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  // Injectable so tests can force deterministic (or jitter-free) backoff delays
  // instead of depending on Math.random.
  backoffOptions?: BackoffOptions;
  // When set, the listener pages through all historical events from this ledger
  // before entering normal live polling. Each page is consumed immediately
  // (without sleeping pollIntervalMs between pages); the listener only switches
  // to interval-based polling once a page returns zero events.
  startLedger?: number;
  // 'poll' (default): fixed-interval polling, always sleeps pollIntervalMs
  // between each call regardless of whether events were returned.
  // 'stream': polls again immediately when events were returned, reducing
  // latency for high-activity contracts; falls back to pollIntervalMs when
  // a poll returns empty (quiet period).
  mode?: 'poll' | 'stream';
  /**
   * Optional metrics registry.  Pass a `MetricsRegistry` instance to record
   * per-phase counters and latency histograms.  When omitted (or when a
   * `NoopMetricsRegistry` is passed) all instrumentation is zero-overhead.
   */
  metrics?: AnyMetricsRegistry;
  /**
   * Optional tracer for OpenTelemetry-compatible distributed tracing.
   * When omitted, a no-op tracer is used — zero overhead and no exports.
   *
   * To enable tracing, pass a `DefaultTracer` configured with an exporter:
   * ```ts
   * import { DefaultTracer } from 'horizon-listener';
   * const tracer = new DefaultTracer({
   *   serviceName: 'horizon-listener',
   *   exporter: async (span) => { await otlpExporter.export(span); },
   * });
   * ```
   */
  tracer?: AnyTracer;
  /**
   * Maximum number of events processed in parallel within a page. Defaults
   * to 1 (strictly sequential). Events sharing an ordering key are always
   * processed in order; the cursor only advances once the whole page is done,
   * so no unprocessed event is ever skipped and no new page is fetched while
   * handlers are still in flight (backpressure).
   */
  concurrency?: number;
  /**
   * How events are grouped for ordering when `concurrency > 1`.
   * 'contract' (default): events from the same contract run in order.
   * 'none': no ordering guarantee between any events.
   */
  orderingKey?: 'contract' | 'none';
}

// Below this, polling a remote Soroban RPC is almost certainly a misconfiguration
// (e.g. `50` typed instead of `5000`) and risks provider rate-limiting.
export const MIN_RECOMMENDED_POLL_INTERVAL_MS = 250;

const defaultSleep = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error('Sleep aborted'));
      return;
    }
    const timeoutId = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timeoutId);
        reject(signal.reason ?? new Error('Sleep aborted'));
      },
      { once: true },
    );
  });

export class HorizonListener {
  private readonly eventSource: EventSource;
  private readonly onEvent: (event: RawContractEvent) => Promise<void> | void;
  private readonly onEventFailure?: (event: RawContractEvent, error: unknown) => void | Promise<void>;
  private readonly eventRetry?: HorizonListenerOptions['eventRetry'];
  private readonly pollIntervalMs: number;
  private readonly maxRetries: number;
  private readonly logger: Logger;
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  private readonly backoffOptions: BackoffOptions;
  private readonly mode: 'poll' | 'stream';
  private readonly metrics: AnyMetricsRegistry;
  private readonly tracer: AnyTracer;
  private readonly concurrency: number;
  private readonly orderingKey: 'contract' | 'none';

  private cursor: string | undefined;
  private running = false;
  private attempt = 0;
  private backfilling = false;
  private sleepAbortController: AbortController | undefined;

  constructor(options: HorizonListenerOptions) {
    this.eventSource = options.eventSource;
    this.onEvent = options.onEvent;
    this.onEventFailure = options.onEventFailure;
    this.eventRetry = options.eventRetry;
    this.pollIntervalMs = options.pollIntervalMs ?? 5000;
    this.maxRetries = options.maxRetries ?? 10;
    this.logger = options.logger ?? consoleLogger;
    if (this.pollIntervalMs < MIN_RECOMMENDED_POLL_INTERVAL_MS) {
      this.logger.warn(
        `horizon-listener: pollIntervalMs is ${this.pollIntervalMs}ms, below the recommended ` +
          `minimum of ${MIN_RECOMMENDED_POLL_INTERVAL_MS}ms; this may hammer the Soroban RPC ` +
          'endpoint and get throttled. Ignore this warning for local low-latency testing.',
      );
    }
    this.sleep = options.sleep ?? defaultSleep;
    this.backoffOptions = options.backoffOptions ?? {};
    this.backfilling = options.startLedger != null;
    this.mode = options.mode ?? 'poll';
    this.metrics = options.metrics ?? new NoopMetricsRegistry();
    this.tracer = options.tracer ?? new NoopTracer();
    this.concurrency = Math.max(1, Math.floor(options.concurrency ?? 1));
    this.orderingKey = options.orderingKey ?? 'contract';
  }

  // Soroban RPC's getEvents is a polling/cursor API, not a persistent stream, so
  // "reconnecting" here just means: pause, then poll again with backoff.
  /**
   * Starts the event listener loop.
   * @throws {Error} When max retries are exceeded for consecutive polling failures.
   * This is an unrecoverable error that indicates the listener cannot continue.
   * @throws {CursorOutOfRangeError} When the cursor points at pruned history and `onGap` is `'fail'`.
   *
   * Pass `{ signal }` to stop the listener via an AbortController; the returned
   * promise resolves once the loop has wound down. An already-aborted signal
   * makes this a no-op.
   */
  async start(options: StartOptions = {}): Promise<void> {
    const { signal } = options;
    if (signal?.aborted) return;
    const onAbort = (): void => this.stop();
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      await this.run();
    } finally {
      signal?.removeEventListener('abort', onAbort);
    }
  }

  /**
   * Consume events with `for await`. The listener only moves on to the next
   * event (and only advances its cursor past a page) once the consumer pulls
   * the next item, so a slow consumer applies backpressure to polling.
   * Breaking out of the loop or aborting `signal` stops the listener.
   */
  async *events(options: StartOptions = {}): AsyncGenerator<RawContractEvent, void, undefined> {
    const { signal } = options;
    const queue: Array<{ event: RawContractEvent; ack: () => void }> = [];
    let wake: (() => void) | undefined;
    let done = false;
    let closed = false;
    let failure: unknown;
    const notify = (): void => {
      const w = wake;
      wake = undefined;
      w?.();
    };

    this.handler = (event) =>
      closed || signal?.aborted
        ? undefined
        : new Promise<void>((ack) => {
            queue.push({ event, ack });
            notify();
          });
    const loop = this.start({ signal }).then(
      () => {
        done = true;
        notify();
      },
      (err) => {
        failure = err;
        done = true;
        notify();
      },
    );

    let ack: (() => void) | undefined;
    try {
      while (true) {
        ack?.();
        ack = undefined;
        while (queue.length === 0 && !done) {
          await new Promise<void>((resolve) => (wake = resolve));
        }
        const item = queue.shift();
        if (!item) {
          if (failure !== undefined) throw failure;
          return;
        }
        ack = item.ack;
        yield item.event;
      }
    } finally {
      closed = true;
      this.stop();
      ack?.();
      for (const pending of queue.splice(0)) pending.ack();
      await loop;
      this.handler = this.onEvent;
    }
  }

  private async run(): Promise<void> {
    this.running = true;
    this.attempt = 0;

    while (this.running) {
      // ── rpc_poll span ────────────────────────────────────────────────────
      const pollSpan = this.tracer.startSpan('rpc_poll');
      pollSpan.setAttribute('poll.attempt', this.attempt);

      let response: { events: RawContractEvent[]; nextCursor: string };
      const pollStart = Date.now();
      try {
        response = await this.eventSource.getEvents(this.cursor);
      } catch (err) {
        const pollDuration = Date.now() - pollStart;
        this.metrics.counter.inc('rpc_poll', 'failure');
        this.metrics.histogram.observe('rpc_poll', pollDuration);

        this.attempt += 1;
        pollSpan.setAttribute('poll.attempt', this.attempt);
        pollSpan.end('error', err instanceof Error ? err : new Error(String(err)));

        if (err instanceof CursorOutOfRangeError) {
          if (
            this.onGap === 'skipToOldest' &&
            err.oldestAvailable != null &&
            this.eventSource.resetToLedger
          ) {
            const requested = Number(err.requested);
            const gap = Number.isFinite(requested) ? err.oldestAvailable - requested : 'unknown';
            this.logger.warn(
              `horizon-listener: requested history was pruned; skipping to oldest available ledger ` +
                `${err.oldestAvailable} (gap: ${gap} ledgers)`,
              err,
            );
            this.eventSource.resetToLedger(err.oldestAvailable);
            this.cursor = undefined;
            this.attempt = 0;
            continue;
          }
          this.running = false;
          this.logger.error('horizon-listener: cursor is outside the RPC retention window, stopping', err);
          throw err;
        }

        this.logger.warn(
          `horizon-listener: poll failed (attempt ${this.attempt}/${this.maxRetries}), backing off`,
          err,
        );

        if (this.attempt >= this.maxRetries) {
          this.running = false;
          this.metrics.counter.inc('rpc_poll', 'cancelled');
          // Mark the final poll as cancelled (we gave up, not a transient error)
          this.tracer.startSpan('rpc_poll').end('cancelled');
          throw new Error(
            `horizon-listener: giving up after ${this.attempt} consecutive failed polls`,
          );
        }

        // `attempt` is one-based for retry limits, while backoff uses a zero-based exponent.
        const delayMs = computeBackoffDelayMs(this.attempt - 1, this.backoffOptions);
        this.sleepAbortController = new AbortController();
        try {
          await this.sleep(delayMs, this.sleepAbortController.signal);
        } catch (sleepErr) {
          if (this.sleepAbortController.signal.aborted) {
            break;
          }
          throw sleepErr;
        } finally {
          this.sleepAbortController = undefined;
        }
        continue;
      }

      const pollDuration = Date.now() - pollStart;
      this.metrics.counter.inc('rpc_poll', 'success');
      this.metrics.histogram.observe('rpc_poll', pollDuration);
      this.metrics.gauge.set('rpc_poll', response.events.length);
      pollSpan.setAttribute('poll.event_count', response.events.length);
      pollSpan.end('ok');

      this.attempt = 0;

      const relayContext = { traceId: pollSpan.traceId, spanId: pollSpan.spanId };
      await this.processPage(response.events, relayContext);

      this.cursor = response.nextCursor;
      this.logger.debug('horizon-listener: cursor advanced', this.cursor);

      if (this.backfilling) {
        if (response.events.length === 0) {
          this.backfilling = false;
          this.logger.info('horizon-listener: backfill complete, switching to live polling');
        } else {
          this.logger.debug(
            `horizon-listener: backfill page consumed (${response.events.length} events), fetching next page`,
          );
          if (!this.running) {
            break;
          }
          continue;
        }
      }

      if (!this.running) {
        break;
      }

      // In stream mode, skip sleeping when events were returned so the next
      // page is fetched immediately; only sleep during quiet periods.
      if (this.mode === 'stream' && response.events.length > 0) {
        continue;
      }

      this.sleepAbortController = new AbortController();
      try {
        await this.sleep(this.pollIntervalMs, this.sleepAbortController.signal);
      } catch (sleepErr) {
        if (this.sleepAbortController.signal.aborted) {
          break;
        }
        throw sleepErr;
      } finally {
        this.sleepAbortController = undefined;
      }
    }
  }

  // Processes a page of events. Events with the same ordering key run in
  // sequence; distinct keys run in parallel up to `concurrency`. Resolves only
  // once every event has been handled, so the caller can safely advance the cursor.
  private async processPage(
    events: RawContractEvent[],
    relayContext: TracingContext,
  ): Promise<void> {
    if (this.concurrency <= 1) {
      for (const event of events) {
        await this.processEvent(event, relayContext);
      }
      return;
    }

    const lanes = new Map<string, RawContractEvent[]>();
    events.forEach((event, i) => {
      const key = this.orderingKey === 'contract' ? event.contractId : String(i);
      const lane = lanes.get(key);
      if (lane) lane.push(event);
      else lanes.set(key, [event]);
    });

    const queue = [...lanes.values()];
    const worker = async (): Promise<void> => {
      for (let lane = queue.shift(); lane; lane = queue.shift()) {
        for (const event of lane) {
          await this.processEvent(event, relayContext);
        }
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(this.concurrency, queue.length) }, worker),
    );
  }

  private async processEvent(event: RawContractEvent, relayContext: TracingContext): Promise<void> {
    const relayStart = Date.now();
    // ── event_relay span ───────────────────────────────────────────────
    // Parent is the poll span so spans form a coherent tree:
    // rpc_poll → event_relay (one child per event)
    const relaySpan = this.tracer.startSpan('event_relay', relayContext);
    // Low-cardinality attributes only — event ID and contract ID are stable
    // identifiers, not user-data payloads. The event value is redacted by
    // the tracer (redactPayload: true by default).
    relaySpan.setAttribute('event.id', event.id);
    relaySpan.setAttribute('event.contract_id', event.contractId);
    relaySpan.setAttribute('event.ledger', event.ledger);

    this.logger.info('horizon-listener: received contract event', event);
    const maxEventAttempts = this.eventRetry
      ? Math.max(1, this.eventRetry.maxRetries ?? 3)
      : 1;
    let eventError: unknown;
    let eventSucceeded = false;

    for (let eventAttempt = 1; eventAttempt <= maxEventAttempts; eventAttempt += 1) {
      try {
        await this.onEvent(event);
        eventSucceeded = true;
        break;
      } catch (err) {
        eventError = err;
        if (eventAttempt >= maxEventAttempts) {
          break;
        }

        const delayMs = computeBackoffDelayMs(eventAttempt, this.eventRetry);
        this.logger.warn(
          `horizon-listener: onEvent failed (attempt ${eventAttempt}/${maxEventAttempts}), retrying in ${delayMs}ms`,
          err,
        );
        await this.sleep(delayMs);
      }
    }

    if (eventSucceeded) {
      const relayDuration = Date.now() - relayStart;
      this.metrics.counter.inc('event_relay', 'success');
      this.metrics.histogram.observe('event_relay', relayDuration);
      relaySpan.end('ok');
    } else {
      const relayDuration = Date.now() - relayStart;
      this.logger.error('horizon-listener: onEvent handler threw', eventError);
      this.metrics.counter.inc('event_relay', 'failure');
      this.metrics.histogram.observe('event_relay', relayDuration);
      relaySpan.end(
        'error',
        eventError instanceof Error ? eventError : new Error(String(eventError)),
      );
      if (this.onEventFailure) {
        try {
          await this.onEventFailure(event, eventError);
        } catch (failureErr) {
          this.logger.error('horizon-listener: onEventFailure handler threw', failureErr);
        }
      }
    }
  }

  stop(): void {
    this.running = false;
    this.sleepAbortController?.abort();
  }

  /**
   * Returns a snapshot of the listener's current health/progress state, for
   * use in liveness/readiness probes or status dashboards.
   */
  getStatus(): {
    running: boolean;
    cursor: string | undefined;
    consecutiveFailures: number;
    backfilling: boolean;
  } {
    return {
      running: this.running,
      cursor: this.cursor,
      consecutiveFailures: this.attempt,
      backfilling: this.backfilling,
    };
  }
}
