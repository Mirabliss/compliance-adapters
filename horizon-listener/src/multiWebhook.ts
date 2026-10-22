/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import type { DeadLetterQueue } from './deadLetterQueue';
import type { RawContractEvent } from './eventSource';
import type { WebhookSender } from './webhook';

export interface WebhookTarget {
  /** Human-readable name used in error messages (e.g. `"siem"`). */
  name: string;
  /**
   * The sender for this target. Retry/backoff is owned by the sender itself
   * (e.g. `HttpWebhookSender` with its own `maxRetries`), so each target
   * retries independently of the others.
   */
  sender: WebhookSender;
  /**
   * Required targets must confirm delivery for the event to be acknowledged.
   * Optional targets never block acknowledgement. Defaults to `true`.
   */
  required?: boolean;
  /** Per-target dead-letter queue; receives the event when this target fails. */
  deadLetterQueue?: DeadLetterQueue;
}

export interface MultiWebhookSenderOptions {
  targets: WebhookTarget[];
}

/**
 * Thrown by {@link MultiWebhookSender.send} when one or more required targets
 * failed. `failures` lists every failed target (required and optional).
 */
export class MultiWebhookDeliveryError extends Error {
  constructor(
    message: string,
    public readonly failures: { target: string; required: boolean; error: Error }[],
  ) {
    super(message);
    this.name = 'MultiWebhookDeliveryError';
  }
}

/**
 * Fans each event out to N targets concurrently. Targets fail independently:
 * a slow or failing target never blocks delivery to the others.
 *
 * - `send` resolves once every **required** target has confirmed delivery.
 * - A failed **optional** target is dead-lettered (if it has a DLQ) and
 *   otherwise ignored; the event is still acknowledged.
 * - A failed **required** target is dead-lettered (if it has a DLQ) and `send`
 *   rejects with {@link MultiWebhookDeliveryError}, so the event is not
 *   acknowledged.
 */
export class MultiWebhookSender implements WebhookSender {
  private readonly targets: WebhookTarget[];

  constructor(options: MultiWebhookSenderOptions) {
    if (!options.targets || options.targets.length === 0) {
      throw new Error('horizon-listener: MultiWebhookSender requires at least one target');
    }
    const names = new Set<string>();
    for (const target of options.targets) {
      if (names.has(target.name)) {
        throw new Error(`horizon-listener: MultiWebhookSender duplicate target name "${target.name}"`);
      }
      names.add(target.name);
    }
    this.targets = options.targets;
  }

  async send(event: RawContractEvent): Promise<void> {
    const results = await Promise.allSettled(this.targets.map((target) => target.sender.send(event)));

    const failures: { target: string; required: boolean; error: Error }[] = [];
    await Promise.all(
      results.map(async (result, i) => {
        if (result.status === 'fulfilled') return;
        const target = this.targets[i];
        const error =
          result.reason instanceof Error ? result.reason : new Error(String(result.reason));
        failures.push({ target: target.name, required: target.required ?? true, error });
        await target.deadLetterQueue?.enqueue(event, error);
      }),
    );

    const requiredFailures = failures.filter((failure) => failure.required);
    if (requiredFailures.length > 0) {
      throw new MultiWebhookDeliveryError(
        `horizon-listener: required webhook target(s) failed: ${requiredFailures
          .map((failure) => `${failure.target} (${failure.error.message})`)
          .join(', ')}`,
        failures,
      );
    }
  }
}
