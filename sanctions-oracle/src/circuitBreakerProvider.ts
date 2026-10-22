/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { SanctionsProvider } from './SanctionsProvider';

export type CircuitState = 'closed' | 'open' | 'half-open';

/** Numeric encoding of {@link CircuitState} for the `provider_circuit_state` gauge. */
export const CIRCUIT_STATE_VALUES: Record<CircuitState, number> = {
  closed: 0,
  'half-open': 1,
  open: 2,
};

export const PROVIDER_CIRCUIT_STATE_METRIC = 'provider_circuit_state';

export interface CircuitBreakerOptions {
  /** Consecutive failures that trip the breaker open. Default: 5. */
  failureThreshold?: number;
  /** How long the breaker stays open before allowing a half-open probe. Default: 30000ms. */
  cooldownMs?: number;
  /** Label used for the metric (defaults to `default`). */
  name?: string;
  /** Called on every state transition (e.g. to push the gauge to a metrics backend). */
  onStateChange?: (state: CircuitState, previous: CircuitState) => void;
  /** Clock override for tests. Defaults to `Date.now`. */
  now?: () => number;
}

export class CircuitOpenError extends Error {
  constructor(name: string) {
    super(`sanctions-oracle: circuit breaker "${name}" is open; failing fast`);
    this.name = 'CircuitOpenError';
  }
}

/**
 * Wraps a {@link SanctionsProvider} with a closed/open/half-open circuit
 * breaker so a dead upstream fails fast instead of every address waiting out
 * the full retry/backoff cycle. Composes with `RateLimitedSanctionsProvider`
 * and `ProviderRegistry` since it is itself a `SanctionsProvider`.
 */
export class CircuitBreakerSanctionsProvider implements SanctionsProvider {
  private state: CircuitState = 'closed';
  private failures = 0;
  private openedAt = 0;
  private probeInFlight = false;
  private readonly failureThreshold: number;
  private readonly cooldownMs: number;
  private readonly name: string;
  private readonly now: () => number;
  private readonly onStateChange?: CircuitBreakerOptions['onStateChange'];

  constructor(
    private readonly inner: SanctionsProvider,
    options: CircuitBreakerOptions = {},
  ) {
    this.failureThreshold = options.failureThreshold ?? 5;
    this.cooldownMs = options.cooldownMs ?? 30_000;
    this.name = options.name ?? 'default';
    this.now = options.now ?? Date.now;
    this.onStateChange = options.onStateChange;
  }

  getState(): CircuitState {
    if (this.state === 'open' && this.now() - this.openedAt >= this.cooldownMs) {
      this.transition('half-open');
    }
    return this.state;
  }

  /** Current value of the `provider_circuit_state` gauge (0 closed, 1 half-open, 2 open). */
  getMetricValue(): number {
    return CIRCUIT_STATE_VALUES[this.getState()];
  }

  /** Prometheus text exposition of the `provider_circuit_state` gauge. */
  renderPrometheus(): string {
    return [
      `# HELP ${PROVIDER_CIRCUIT_STATE_METRIC} Circuit breaker state (0=closed, 1=half-open, 2=open)`,
      `# TYPE ${PROVIDER_CIRCUIT_STATE_METRIC} gauge`,
      `${PROVIDER_CIRCUIT_STATE_METRIC}{provider="${this.name}"} ${this.getMetricValue()}`,
      '',
    ].join('\n');
  }

  async checkAddress(address: string): Promise<{ flagged: boolean; source: string }> {
    const state = this.getState();
    if (state === 'open' || (state === 'half-open' && this.probeInFlight)) {
      throw new CircuitOpenError(this.name);
    }
    const isProbe = state === 'half-open';
    if (isProbe) this.probeInFlight = true;
    try {
      const result = await this.inner.checkAddress(address);
      this.failures = 0;
      if (this.state !== 'closed') this.transition('closed');
      return result;
    } catch (error) {
      this.failures += 1;
      if (isProbe || this.failures >= this.failureThreshold) {
        this.openedAt = this.now();
        this.transition('open');
      }
      throw error;
    } finally {
      if (isProbe) this.probeInFlight = false;
    }
  }

  private transition(next: CircuitState): void {
    if (next === this.state) return;
    const previous = this.state;
    this.state = next;
    this.onStateChange?.(next, previous);
  }
}
