/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * horizon-listener — NOTE: despite the name, this package consumes Soroban RPC
 * `getEvents`, not the Horizon REST/SSE API. Point it at a Soroban RPC endpoint.
 * A rename (e.g. `@compliance-adapters/event-listener`) with a deprecation
 * alias is tracked as a follow-up discussion.
 */

export { HorizonListener, type HorizonListenerOptions, type Logger } from './listener';
export {
  RpcEventSource,
  CursorOutOfRangeError,
  toCursorOutOfRangeError,
  type EventSource,
  type RawContractEvent,
  type RpcEventSourceOptions,
  type RpcEventType,
} from './eventSource';
export {
  HorizonEventSource,
  type HorizonEventSourceOptions,
  type HorizonRecord,
} from './horizonEventSource';
export {
  InMemoryDeadLetterQueue,
  FileDeadLetterQueue,
  replayDeadLetterQueue,
  type DeadLetterEvent,
  type DeadLetterQueue,
  type ReplayDeadLetterQueueOptions,
  type ReplayDeadLetterQueueResult,
} from './deadLetterQueue';
export { computeBackoffDelayMs, type BackoffOptions } from '@compliance-adapters/backoff';
export {
  HttpWebhookSender,
  WebhookHttpError,
  WEBHOOK_SCHEMA_VERSION,
  type WebhookSender,
  type HttpWebhookSenderOptions,
} from './webhook';
export {
  MultiWebhookSender,
  MultiWebhookDeliveryError,
  type MultiWebhookSenderOptions,
  type WebhookTarget,
} from './multiWebhook';
export { createWebhookForwarder, type WebhookForwarderOptions } from './factory';
export {
  MetricsRegistry,
  NoopMetricsRegistry,
  DEFAULT_HISTOGRAM_BUCKETS,
  type Phase,
  type AnyMetricsRegistry,
  type Counter,
  type Gauge,
  type Histogram,
  type Outcome,
  type MetricsRegistryOptions,
} from './metrics';
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
  extractTraceContext,
} from './tracing';
