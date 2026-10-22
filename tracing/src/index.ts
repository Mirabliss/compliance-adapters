/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * OpenTelemetry-compatible tracing shared across compliance-adapters packages.
 *
 * Architecture
 * ────────────
 * This module defines its own thin interfaces rather than importing
 * `@opentelemetry/api` directly, keeping the runtime footprint to zero for
 * operators who don't need tracing. Consumers who want real OTLP export can
 * bridge the two worlds by supplying an `exporter` callback that forwards
 * completed `SpanData` objects to their chosen OpenTelemetry SDK exporter.
 *
 * Key design decisions
 * ─────────────────────
 * • No transaction payload by default — event values are redacted unless
 *   `TracingOptions.redactPayload` is explicitly set to `false`.
 * • Exporter failures never propagate — the exporter callback is wrapped in
 *   a try/catch; any error is forwarded to the optional `onExportError` hook
 *   and then swallowed so debugging phases always succeed.
 * • Context propagation — spans carry a W3C `traceparent`-compatible
 *   traceId + spanId and can inject / extract those values as HTTP headers.
 * • Optional sampling — a `sampler` predicate receives the span name and
 *   returns a boolean; defaults to sampling everything.
 * • Graceful shutdown — `Tracer.shutdown()` flushes any pending exporter
 *   calls and resolves once they settle.
 *
 * Consuming packages layer their own phase-specific span-naming conventions
 * on top of this generic machinery (e.g. horizon-listener's `rpc_poll` /
 * `event_relay` / `webhook` phases, sanctions-oracle's `address_check` /
 * `denylist_write` phases).
 */

import { randomBytes } from 'crypto';
import type {
  SpanStatus,
  SpanAttributes,
  SpanData,
  TracingContext,
} from '@compliance-adapters/tracing-types';
export type { SpanStatus, SpanAttributes, SpanData, TracingContext };

// ── Span data model ───────────────────────────────────────────────────────────

// ── Live span handle ──────────────────────────────────────────────────────────

export interface Span {
  readonly traceId: string;
  readonly spanId: string;
  /** Attach a low-cardinality attribute.  Payload attributes should not be set
   *  unless the caller has disabled payload redaction. */
  setAttribute(key: string, value: string | number | boolean): void;
  end(status?: SpanStatus, error?: Error): void;
}

// ── Tracer interface ──────────────────────────────────────────────────────────

export interface Tracer {
  /** Start a new span. If `parentContext` is provided, the new span is a child. */
  startSpan(name: string, parentContext?: TracingContext): Span;
  /**
   * Extract a `TracingContext` from W3C `traceparent` header format.
   * Returns `undefined` if the header is absent or malformed.
   */
  extractContext(traceparent: string | undefined): TracingContext | undefined;
  /**
   * Inject a context into a `traceparent` header string.
   * Useful for propagating context to outbound HTTP calls.
   */
  injectContext(context: TracingContext): string;
  /**
   * Flush any pending exporter calls and shut down.
   * Returns a promise that resolves once all in-flight exports settle.
   */
  shutdown(): Promise<void>;
}

// ── Exporter callback ─────────────────────────────────────────────────────────

/**
 * Called with each completed `SpanData` after the span ends.
 * May be async; errors thrown are caught and forwarded to `onExportError`.
 */
export type SpanExporter = (span: SpanData) => void | Promise<void>;

// ── Tracing options ───────────────────────────────────────────────────────────

export interface TracingOptions {
  /**
   * Called with each completed span.  May forward to any OTLP/Jaeger/Zipkin
   * SDK exporter.  When omitted, spans are silently discarded.
   */
  exporter?: SpanExporter;
  /**
   * Optional predicate controlling which span names are sampled.
   * Receives the span name; return `true` to record the span.
   * Defaults to `() => true` (sample everything).
   */
  sampler?: (spanName: string) => boolean;
  /**
   * Probabilistic sampling ratio in [0, 1]. Root spans are sampled with
   * `Math.random() < sampleRate`; children inherit the parent decision
   * (parent-based sampling) via `TracingContext.sampled`. Unsampled spans
   * become cheap no-ops. Defaults to 1 (sample everything). When both
   * `sampler` and `sampleRate` are set, both must allow the span.
   */
  sampleRate?: number;
  /**
   * When `true` (default), event/payload data is NOT attached to spans.
   * Set to `false` only in environments where payload logging is acceptable.
   */
  redactPayload?: boolean;
  /**
   * Called when the exporter throws.  Useful for surfacing export errors
   * in tests or logs without propagating them.
   */
  onExportError?: (error: unknown) => void;
  /** Optional service name added as an attribute to every span. */
  serviceName?: string;
}

// ── ID generation ─────────────────────────────────────────────────────────────

/**
 * Generates a cryptographically strong hex identifier. `Math.random()` is not
 * a strong source of randomness and its collision/predictability weaknesses
 * risk merging unrelated traces in high-throughput producers.
 */
function randomHex(bytes: number): string {
  return randomBytes(bytes).toString('hex');
}

// ── Live span implementation ──────────────────────────────────────────────────

class LiveSpan implements Span {
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId: string | undefined;
  private readonly name: string;
  private readonly startTimeMs: number;
  private readonly attrs: SpanAttributes;
  private ended = false;

  private readonly onEnd: (data: SpanData) => void;

  constructor(
    name: string,
    traceId: string,
    spanId: string,
    parentSpanId: string | undefined,
    startTimeMs: number,
    serviceName: string | undefined,
    onEnd: (data: SpanData) => void,
  ) {
    this.name = name;
    this.traceId = traceId;
    this.spanId = spanId;
    this.parentSpanId = parentSpanId;
    this.startTimeMs = startTimeMs;
    this.attrs = serviceName ? { 'service.name': serviceName } : {};
    this.onEnd = onEnd;
  }

  setAttribute(key: string, value: string | number | boolean): void {
    this.attrs[key] = value;
  }

  end(status: SpanStatus = 'ok', error?: Error): void {
    if (this.ended) return;
    this.ended = true;

    const endTimeMs = Date.now();
    this.onEnd({
      traceId: this.traceId,
      spanId: this.spanId,
      parentSpanId: this.parentSpanId,
      name: this.name,
      startTimeMs: this.startTimeMs,
      endTimeMs,
      durationMs: endTimeMs - this.startTimeMs,
      status,
      attributes: { ...this.attrs },
      errorMessage: error?.message,
    });
  }
}

// ── Noop span ─────────────────────────────────────────────────────────────────

class NoopSpan implements Span {
  readonly traceId = '';
  readonly spanId = '';
  setAttribute(_key: string, _value: string | number | boolean): void {}
  end(_status?: SpanStatus, _error?: Error): void {}
}

// ── DefaultTracer ────────────────────────────────────────────────────────────

/**
 * A fully functional tracer that records spans and exports them via the
 * provided `exporter` callback. When no exporter is provided, spans are
 * still recorded in-memory but export is skipped.
 */
export class DefaultTracer implements Tracer {
  private readonly options: Required<
    Omit<TracingOptions, 'exporter' | 'onExportError' | 'serviceName' | 'sampleRate'>
  > & {
    exporter: SpanExporter | undefined;
    onExportError: ((error: unknown) => void) | undefined;
    serviceName: string | undefined;
    sampleRate: number | undefined;
  };
  private readonly pending: Promise<void>[] = [];
  private shuttingDown = false;

  constructor(options: TracingOptions = {}) {
    if (options.sampleRate !== undefined && (options.sampleRate < 0 || options.sampleRate > 1 || Number.isNaN(options.sampleRate))) {
      throw new Error(`tracing: sampleRate must be in [0, 1], got ${options.sampleRate}`);
    }
    this.options = {
      exporter: options.exporter,
      sampler: options.sampler ?? (() => true),
      sampleRate: options.sampleRate,
      redactPayload: options.redactPayload !== false, // default true
      onExportError: options.onExportError,
      serviceName: options.serviceName,
    };
  }

  startSpan(name: string, parentContext?: TracingContext): Span {
    if (this.shuttingDown) return new NoopSpan();
    // Parent-based sampling: inherit an explicit parent decision first.
    if (parentContext?.sampled !== undefined) {
      if (!parentContext.sampled) return new NoopSpan();
    } else {
      if (!this.options.sampler(name)) return new NoopSpan();
      const rate = this.options.sampleRate;
      if (rate !== undefined && !(rate >= 1) && (rate <= 0 || Math.random() >= rate)) {
        return new NoopSpan();
      }
    }

    const traceId = parentContext?.traceId ?? randomHex(16);
    const spanId = randomHex(8);
    const parentSpanId = parentContext?.spanId;

    return new LiveSpan(
      name,
      traceId,
      spanId,
      parentSpanId,
      Date.now(),
      this.options.serviceName,
      (data) => this.handleSpanEnd(data),
    );
  }

  extractContext(traceparent: string | undefined): TracingContext | undefined {
    if (!traceparent) return undefined;
    // W3C traceparent format: version-traceId-parentId-traceFlags
    // e.g. "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    const parts = traceparent.split('-');
    if (parts.length < 4 || parts[1].length !== 32 || parts[2].length !== 16) {
      return undefined;
    }
    return { traceId: parts[1], spanId: parts[2], sampled: parts[3] === '01' };
  }

  injectContext(context: TracingContext): string {
    return `00-${context.traceId}-${context.spanId}-${context.sampled === false ? '00' : '01'}`;
  }

  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    // Wait for all in-flight exporter calls to settle
    await Promise.allSettled(this.pending);
  }

  private handleSpanEnd(data: SpanData): void {
    if (!this.options.exporter) return;

    const exportPromise = Promise.resolve()
      .then(() => this.options.exporter!(data))
      .catch((err) => {
        // Exporter failures never surface to the caller
        this.options.onExportError?.(err);
      })
      .finally(() => {
        const idx = this.pending.indexOf(exportPromise);
        if (idx !== -1) this.pending.splice(idx, 1);
      });

    this.pending.push(exportPromise);
  }
}

// ── NoopTracer ────────────────────────────────────────────────────────────────

/**
 * A no-op tracer that creates no spans and never calls any exporter.
 * Used as the default when tracing is not configured — zero overhead.
 */
export class NoopTracer implements Tracer {
  startSpan(_name: string, _parentContext?: TracingContext): Span {
    return new NoopSpan();
  }

  extractContext(_traceparent: string | undefined): TracingContext | undefined {
    return undefined;
  }

  injectContext(context: TracingContext): string {
    return `00-${context.traceId}-${context.spanId}-${context.sampled === false ? '00' : '01'}`;
  }

  async shutdown(): Promise<void> {}
}

export function extractTraceContext(
  headers: Record<string, string | string[] | undefined> | Headers,
  tracer?: Tracer,
): TracingContext | undefined {
  let raw: string | undefined;
  if (typeof (headers as Headers).get === 'function') {
    raw = (headers as Headers).get('traceparent') ?? undefined;
  } else {
    const rec = headers as Record<string, string | string[] | undefined>;
    for (const key of Object.keys(rec ?? {})) {
      if (key.toLowerCase() === 'traceparent') {
        const v = rec[key];
        raw = Array.isArray(v) ? v[0] : v;
        break;
      }
    }
  }
  if (!raw) return undefined;
  return (tracer ?? new DefaultTracer()).extractContext(raw);
}

export type AnyTracer = DefaultTracer | NoopTracer;

// ── OpenTelemetry bridge ──────────────────────────────────────────────────────

/**
 * Minimal structural view of an OpenTelemetry span. Declared locally so
 * `@opentelemetry/api` stays an optional peer dependency — this module never
 * imports it at runtime.
 */
export interface OtelSpanLike {
  setAttribute(key: string, value: string | number | boolean): unknown;
  setStatus(status: { code: number; message?: string }): unknown;
  recordException?(error: Error): unknown;
  end(): void;
  spanContext?(): { traceId: string; spanId: string };
}

/**
 * Minimal structural view of an OpenTelemetry tracer (e.g. the result of
 * `trace.getTracer(name)` from `@opentelemetry/api`).
 */
export interface OtelTracerLike {
  startSpan(name: string, options?: unknown, context?: unknown): OtelSpanLike;
}

/** OTel `SpanStatusCode`: UNSET=0, OK=1, ERROR=2. */
const OTEL_STATUS = { UNSET: 0, OK: 1, ERROR: 2 } as const;

class OtelSpanAdapter implements Span {
  readonly traceId: string;
  readonly spanId: string;

  constructor(
    private readonly otelSpan: OtelSpanLike,
    traceId: string,
    spanId: string,
  ) {
    this.traceId = traceId;
    this.spanId = spanId;
  }

  setAttribute(key: string, value: string | number | boolean): void {
    this.otelSpan.setAttribute(key, value);
  }

  end(status: SpanStatus = 'ok', error?: Error): void {
    if (status === 'ok') {
      this.otelSpan.setStatus({ code: OTEL_STATUS.OK });
    } else if (status === 'error') {
      this.otelSpan.setStatus({ code: OTEL_STATUS.ERROR, message: error?.message });
      if (error && typeof this.otelSpan.recordException === 'function') {
        this.otelSpan.recordException(error);
      }
    } else {
      this.otelSpan.setStatus({ code: OTEL_STATUS.ERROR, message: 'cancelled' });
    }
    this.otelSpan.end();
  }
}

class OtelTracerAdapter implements Tracer {
  constructor(private readonly otelTracer: OtelTracerLike) {}

  startSpan(name: string, _parentContext?: TracingContext): Span {
    const otelSpan = this.otelTracer.startSpan(name);
    const ctx = typeof otelSpan.spanContext === 'function' ? otelSpan.spanContext() : undefined;
    return new OtelSpanAdapter(
      otelSpan,
      ctx?.traceId ?? randomHex(16),
      ctx?.spanId ?? randomHex(8),
    );
  }

  extractContext(traceparent: string | undefined): TracingContext | undefined {
    if (!traceparent) return undefined;
    const parts = traceparent.split('-');
    if (parts.length < 4 || parts[1].length !== 32 || parts[2].length !== 16) {
      return undefined;
    }
    return { traceId: parts[1], spanId: parts[2] };
  }

  injectContext(context: TracingContext): string {
    return `00-${context.traceId}-${context.spanId}-01`;
  }

  async shutdown(): Promise<void> {}
}

/**
 * Bridge the internal {@link Tracer} interface on top of an OpenTelemetry
 * tracer, enabling export to Jaeger, Tempo, Datadog, or any OTel backend.
 *
 * `@opentelemetry/api` is an optional peer dependency — pass any object
 * satisfying the {@link OtelTracerLike} shape (e.g. `trace.getTracer(name)`).
 *
 * Status mapping: `ok` → `SpanStatusCode.OK`, `error` → `ERROR` (with the
 * error message), `cancelled` → `ERROR` with message `'cancelled'`.
 *
 * @example
 * ```ts
 * import { trace } from '@opentelemetry/api';
 * import { createOtelTracer } from '@compliance-adapters/tracing';
 *
 * const tracer = createOtelTracer(trace.getTracer('compliance-adapters'));
 * const span = tracer.startSpan('address_check');
 * span.setAttribute('phase', 'address_check');
 * span.end('ok');
 * ```
 */
export function createOtelTracer(otelTracer: OtelTracerLike): Tracer {
  return new OtelTracerAdapter(otelTracer);
}
