/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * Lightweight, zero-dependency metrics shared across compliance-adapters
 * packages.
 *
 * Design goals
 * ─────────────
 * • Low-cardinality: labels are `phase` and `outcome` only. Consuming
 *   packages supply their own bounded `Phase` union (e.g. horizon-listener's
 *   `'rpc_poll' | 'event_relay' | 'webhook'`) — never ledger IDs, contract
 *   addresses, transaction hashes, or cursor values.
 * • Prometheus-compatible: `MetricsRegistry.expose()` returns a Prometheus
 *   text-format string suitable for scraping from a `/metrics` endpoint.
 * • Optional: `NoopMetricsRegistry` is a zero-overhead default. Operators who
 *   want visibility pass their own `MetricsRegistry` instance; code paths
 *   that receive no registry stay completely side-effect-free.
 */

export type Outcome = 'success' | 'failure' | 'cancelled';

/** A single counter: monotonically increasing integer keyed by phase+outcome. */
export interface Counter<Phase extends string> {
  inc(phase: Phase, outcome: Outcome): void;
  get(phase: Phase, outcome: Outcome): number;
}

/**
 * A histogram that tracks duration samples in configurable buckets (ms).
 * Exposes `count`, `sum`, and per-bucket cumulative counts for Prometheus.
 */
export interface Histogram<Phase extends string> {
  observe(phase: Phase, durationMs: number): void;
  /**
   * Returns `{ count, sum, buckets }` for a given phase.
   * `buckets` maps upper-bound (ms) → cumulative count of observations ≤ that
   * bound. An `+Inf` bucket is appended automatically.
   */
  snapshot(phase: Phase): { count: number; sum: number; buckets: Map<number | '+Inf', number> };
}

/**
 * A gauge holding a current value (e.g. queue depth, ledger lag, cache size)
 * that can go up and down, keyed by phase.
 */
export interface Gauge<Phase extends string> {
  set(phase: Phase, value: number): void;
  inc(phase: Phase, amount?: number): void;
  dec(phase: Phase, amount?: number): void;
  get(phase: Phase): number;
}

// ── Counter implementation ────────────────────────────────────────────────────

class DefaultCounter<Phase extends string> implements Counter<Phase> {
  private readonly data = new Map<string, number>();

  private key(phase: Phase, outcome: Outcome): string {
    return `${phase}:${outcome}`;
  }

  inc(phase: Phase, outcome: Outcome): void {
    const k = this.key(phase, outcome);
    this.data.set(k, (this.data.get(k) ?? 0) + 1);
  }

  get(phase: Phase, outcome: Outcome): number {
    return this.data.get(this.key(phase, outcome)) ?? 0;
  }
}

// ── Histogram implementation ──────────────────────────────────────────────────

/**
 * Default bucket upper-bounds (ms).  They cover sub-millisecond fast paths all
 * the way through 10 s network timeouts typical for RPC calls.
 */
export const DEFAULT_HISTOGRAM_BUCKETS = [5, 25, 100, 250, 500, 1000, 2500, 5000, 10000];

class DefaultHistogram<Phase extends string> implements Histogram<Phase> {
  private readonly buckets: number[];
  // phase → raw observation list
  private readonly observations = new Map<Phase, number[]>();

  constructor(buckets: number[] = DEFAULT_HISTOGRAM_BUCKETS) {
    this.buckets = [...buckets].sort((a, b) => a - b);
  }

  observe(phase: Phase, durationMs: number): void {
    if (!this.observations.has(phase)) {
      this.observations.set(phase, []);
    }
    this.observations.get(phase)!.push(durationMs);
  }

  snapshot(phase: Phase): { count: number; sum: number; buckets: Map<number | '+Inf', number> } {
    const obs = this.observations.get(phase) ?? [];
    const count = obs.length;
    const sum = obs.reduce((acc, v) => acc + v, 0);

    const bucketMap = new Map<number | '+Inf', number>();
    for (const bound of this.buckets) {
      const cumulative = obs.filter((v) => v <= bound).length;
      bucketMap.set(bound, cumulative);
    }
    // +Inf bucket always equals total count (all observations are ≤ infinity)
    bucketMap.set('+Inf', count);

    return { count, sum, buckets: bucketMap };
  }
}

// ── Gauge implementation ──────────────────────────────────────────────────────

class DefaultGauge<Phase extends string> implements Gauge<Phase> {
  private readonly values = new Map<Phase, number>();

  set(phase: Phase, value: number): void {
    this.values.set(phase, value);
  }

  inc(phase: Phase, amount = 1): void {
    this.values.set(phase, (this.values.get(phase) ?? 0) + amount);
  }

  dec(phase: Phase, amount = 1): void {
    this.values.set(phase, (this.values.get(phase) ?? 0) - amount);
  }

  get(phase: Phase): number {
    return this.values.get(phase) ?? 0;
  }
}

// ── No-op implementations (disabled metrics) ─────────────────────────────────

class NoopCounter<Phase extends string> implements Counter<Phase> {
  inc(_phase: Phase, _outcome: Outcome): void {}
  get(_phase: Phase, _outcome: Outcome): number {
    return 0;
  }
}

class NoopHistogram<Phase extends string> implements Histogram<Phase> {
  observe(_phase: Phase, _durationMs: number): void {}
  snapshot(_phase: Phase): { count: number; sum: number; buckets: Map<number | '+Inf', number> } {
    return { count: 0, sum: 0, buckets: new Map() };
  }
}

class NoopGauge<Phase extends string> implements Gauge<Phase> {
  set(_phase: Phase, _value: number): void {}
  inc(_phase: Phase, _amount?: number): void {}
  dec(_phase: Phase, _amount?: number): void {}
  get(_phase: Phase): number {
    return 0;
  }
}

// ── Registry ──────────────────────────────────────────────────────────────────

export interface MetricsRegistryOptions<Phase extends string> {
  /** All phase values the registry should expose in `expose()`. */
  phases: Phase[];
  /** Prefix prepended to every metric name. */
  prefix: string;
  /** Custom histogram bucket boundaries in milliseconds. */
  histogramBuckets?: number[];
}

/**
 * Holds a counter and a histogram for a package's phases.
 *
 * Pass an instance to a package's options to enable recording. Omit it
 * entirely to use the built-in no-op registry — there is zero overhead.
 */
export class MetricsRegistry<Phase extends string> {
  readonly counter: Counter<Phase>;
  readonly histogram: Histogram<Phase>;
  readonly gauge: Gauge<Phase>;
  private readonly prefix: string;
  private readonly phases: Phase[];

  constructor(options: MetricsRegistryOptions<Phase>) {
    this.prefix = options.prefix;
    this.phases = options.phases;
    this.counter = new DefaultCounter<Phase>();
    this.histogram = new DefaultHistogram<Phase>(options.histogramBuckets);
    this.gauge = new DefaultGauge<Phase>();
  }

  /**
   * Emit a Prometheus text-format exposition for all tracked metrics.
   *
   * Example output:
   * ```
   * # HELP horizon_listener_requests_total Total requests by phase and outcome
   * # TYPE horizon_listener_requests_total counter
   * horizon_listener_requests_total{phase="rpc_poll",outcome="success"} 42
   * ...
   * # HELP horizon_listener_duration_ms_bucket Histogram of phase durations (ms)
   * # TYPE horizon_listener_duration_ms histogram
   * horizon_listener_duration_ms_bucket{phase="rpc_poll",le="5"} 3
   * ...
   * ```
   */
  expose(): string {
    const lines: string[] = [];

    // ── Counter ──────────────────────────────────────────────────────────────
    const counterName = `${this.prefix}_requests_total`;
    lines.push(`# HELP ${counterName} Total requests by phase and outcome`);
    lines.push(`# TYPE ${counterName} counter`);

    const outcomes: Outcome[] = ['success', 'failure', 'cancelled'];

    for (const phase of this.phases) {
      for (const outcome of outcomes) {
        const v = this.counter.get(phase, outcome);
        lines.push(`${counterName}{phase="${phase}",outcome="${outcome}"} ${v}`);
      }
    }

    // ── Histogram ────────────────────────────────────────────────────────────
    const histName = `${this.prefix}_duration_ms`;
    lines.push(`# HELP ${histName}_bucket Histogram of phase durations in milliseconds`);
    lines.push(`# TYPE ${histName} histogram`);

    for (const phase of this.phases) {
      const { count, sum, buckets } = this.histogram.snapshot(phase);
      for (const [le, cumCount] of buckets) {
        lines.push(`${histName}_bucket{phase="${phase}",le="${String(le)}"} ${cumCount}`);
      }
      lines.push(`${histName}_sum{phase="${phase}"} ${sum}`);
      lines.push(`${histName}_count{phase="${phase}"} ${count}`);
    }

    // ── Gauge ────────────────────────────────────────────────────────────────
    const gaugeName = `${this.prefix}_gauge`;
    lines.push(`# HELP ${gaugeName} Current gauge value by phase`);
    lines.push(`# TYPE ${gaugeName} gauge`);
    for (const phase of this.phases) {
      lines.push(`${gaugeName}{phase="${phase}"} ${this.gauge.get(phase)}`);
    }

    return lines.join('\n') + '\n';
  }
}

// ── Shared no-op singleton ────────────────────────────────────────────────────

/**
 * A no-op registry that discards all observations.
 * Used as the default so callers that don't provide a registry pay no cost.
 */
export class NoopMetricsRegistry<Phase extends string> {
  readonly counter: Counter<Phase> = new NoopCounter<Phase>();
  readonly histogram: Histogram<Phase> = new NoopHistogram<Phase>();
  readonly gauge: Gauge<Phase> = new NoopGauge<Phase>();

  expose(): string {
    return '';
  }
}

export type AnyMetricsRegistry<Phase extends string> =
  MetricsRegistry<Phase> | NoopMetricsRegistry<Phase>;
