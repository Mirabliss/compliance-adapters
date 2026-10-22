/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * OpenTelemetry-compatible tracing for sanctions-oracle.
 *
 * The generic tracer machinery is implemented and audited in
 * `@compliance-adapters/tracing`. This package intentionally re-exports that
 * implementation so every adapter shares one RNG and one span lifecycle model.
 */

export {
  DefaultTracer,
  NoopTracer,
  type AnyTracer,
  type Tracer,
  type Span,
  type SpanData,
  type SpanStatus,
  type SpanAttributes,
  type SpanExporter,
  type TracingContext,
  type TracingOptions,
} from '@compliance-adapters/tracing';
export { extractTraceContext } from '@compliance-adapters/tracing';
