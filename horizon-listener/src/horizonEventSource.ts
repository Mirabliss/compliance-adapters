/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import type { EventSource, RawContractEvent } from './eventSource';

/** Minimal shape of a Horizon operation/effect record we map from. */
export interface HorizonRecord {
  paging_token: string;
  type?: string;
  account?: string;
  source_account?: string;
  ledger?: number;
  created_at?: string;
  [key: string]: unknown;
}

export interface HorizonEventSourceOptions {
  /** Base Horizon URL, e.g. `https://horizon.stellar.org`. */
  horizonUrl: string;
  /** When set, streams operations/effects for this account only. */
  accountId?: string;
  /** Which Horizon collection to stream. Defaults to `operations`. */
  endpoint?: 'operations' | 'effects';
  /** Page size per `getEvents` call. Defaults to 10. */
  limit?: number;
  /** Injectable fetch (defaults to global `fetch`); used by tests to mock Horizon. */
  fetchFn?: typeof fetch;
  /** Request timeout in milliseconds. Defaults to no timeout. */
  timeoutMs?: number;
}

/**
 * An {@link EventSource} backed by Horizon's classic operations/effects
 * streaming endpoints. Covers compliance-relevant classic events that are not
 * Soroban events — e.g. `set_trust_line_flags`, `clawback` and account
 * signer/flag changes — mapped onto the common {@link RawContractEvent} shape.
 *
 * Pagination follows Horizon cursors: pass the returned `nextCursor` back as
 * the next call's `cursor` to resume. `nextCursor` is the last record's
 * `paging_token`, falling back to the input cursor when the page is empty.
 */
export class HorizonEventSource implements EventSource {
  private readonly options: Required<
    Pick<HorizonEventSourceOptions, 'horizonUrl' | 'endpoint' | 'limit'>
  > &
    HorizonEventSourceOptions;

  constructor(options: HorizonEventSourceOptions) {
    if (!options.horizonUrl) {
      throw new Error('horizon-listener: HorizonEventSource requires `horizonUrl`');
    }
    this.options = {
      ...options,
      endpoint: options.endpoint ?? 'operations',
      limit: options.limit ?? 10,
    };
  }

  private collectionPath(): string {
    const base = this.options.horizonUrl.replace(/\/+$/, '');
    const { accountId, endpoint } = this.options;
    return accountId
      ? `${base}/accounts/${accountId}/${endpoint}`
      : `${base}/${endpoint}`;
  }

  async getEvents(
    cursor: string | undefined,
  ): Promise<{ events: RawContractEvent[]; nextCursor: string }> {
    const fetchFn = this.options.fetchFn ?? fetch;
    const params = new URLSearchParams({
      order: 'asc',
      limit: String(this.options.limit),
      include_failed: 'true',
    });
    if (cursor) params.set('cursor', cursor);
    const url = `${this.collectionPath()}?${params.toString()}`;

    const fetchPromise = fetchFn(url, { headers: { Accept: 'application/json' } });
    const response = this.options.timeoutMs
      ? await Promise.race([
          fetchPromise,
          new Promise<never>((_, reject) =>
            setTimeout(
              () => reject(new Error(`Horizon request timeout after ${this.options.timeoutMs}ms`)),
              this.options.timeoutMs,
            ),
          ),
        ])
      : await fetchPromise;

    if (!response.ok) {
      throw new Error(
        `horizon-listener: Horizon request failed with status ${response.status} for ${this.options.endpoint}`,
      );
    }
    const body = (await response.json()) as {
      _embedded?: { records?: HorizonRecord[] };
    };
    const records = body._embedded?.records ?? [];

    const events: RawContractEvent[] = records.map((record) => {
      const id = String(record.paging_token ?? record.id ?? '');
      const ledger =
        typeof record.ledger === 'number' && Number.isFinite(record.ledger) ? record.ledger : 0;
      const account = String(
        record.account ?? record.source_account ?? this.options.accountId ?? '',
      );
      const topic = [String(record.type ?? this.options.endpoint)];
      return {
        id,
        contractId: account,
        ledger,
        topic,
        value: record,
      };
    });

    const nextCursor =
      events.length > 0 ? events[events.length - 1].id : (cursor ?? '');
    return { events, nextCursor };
  }
}
