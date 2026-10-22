/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * Shared, runtime-free tracing type definitions.
 *
 * `horizon-listener` and `sanctions-oracle` each ship their own tracer
 * implementation, but the on-the-wire data model — the completed-span
 * snapshot and the propagatable trace context — is identical between them.
 * Defining those shapes here once gives both packages a single nominal
 * origin, so a `TracingContext` produced by one package's tracer can be
 * passed straight into the other's `startSpan(name, parentContext)` for
 * cross-package trace correlation.
 *
 * This package contains types only — importing it adds no runtime
 * dependency and no code to any bundle.
 */

/** Terminal state of a span. */
export type SpanStatus = 'ok' | 'error' | 'cancelled';

/** Low-cardinality attributes only — no transaction payloads or user paths. */
export interface SpanAttributes {
  [key: string]: string | number | boolean | undefined;
}

/** Immutable snapshot of a completed span, ready for export. */
export interface SpanData {
  /** 32-hex-character W3C-compatible trace identifier. */
  traceId: string;
  /** 16-hex-character W3C-compatible span identifier. */
  spanId: string;
  /** spanId of the parent span, or undefined for the root. */
  parentSpanId: string | undefined;
  name: string;
  startTimeMs: number;
  endTimeMs: number;
  durationMs: number;
  status: SpanStatus;
  /** Low-cardinality attributes only — no transaction payloads or user paths. */
  attributes: SpanAttributes;
  /** Error message if status === 'error'. */
  errorMessage?: string;
}

/**
 * The minimal context needed to make a new span a child of an existing one,
 * including across a package or process boundary.
 */
export interface TracingContext {
  traceId: string;
  spanId: string;
  /**
   * Sampling decision carried via W3C trace-flags (`01` = sampled).
   * When present, child spans inherit it (parent-based sampling).
   */
  sampled?: boolean;
}
