/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { rpc } from '@stellar/stellar-sdk';

/**
 * A normalised representation of a single Soroban contract event as returned
 * by the Soroban RPC `getEvents` endpoint.
 *
 * Field shapes are derived from the Stellar SDK's `rpc.Server.getEvents`
 * response. Only the fields needed by the listener pipeline are surfaced here;
 * the rest are intentionally dropped so downstream code isn't coupled to every
 * SDK version's response shape.
 */
export interface RawContractEvent {
  /**
   * Opaque, globally-unique event identifier assigned by the Soroban RPC
   * node. Formatted as `<ledger_sequence>-<event_index>` (e.g.
   * `"4611686018427388004-1"`). Safe to use as a pagination cursor — passing
   * it back as the `cursor` argument to {@link EventSource.getEvents} will
   * resume the stream from the event that immediately follows this one.
   */
  id: string;

  /**
   * The `C…` StrKey-encoded Soroban contract address that emitted the event.
   * Useful for routing events to the correct handler when a single listener
   * subscribes to multiple contracts.
   */
  contractId: string;

  /**
   * The ledger sequence number in which this event was included. Monotonically
   * increasing; can be used to track the highest processed ledger and choose a
   * safe `startLedger` value on restart.
   */
  ledger: number;

  /**
   * Ordered list of topic segments that categorise the event. Each element is
   * the result of calling `String()` on the raw SDK topic value, which
   * serialises Soroban `ScVal` topic entries as their human-readable string
   * representation (e.g. `"SymbolSmall(add)"`, `"Address(G…)"`) rather than
   * raw bytes. Consumers that need the original `ScVal` structure should parse
   * these strings or extend this interface to carry the raw SDK value instead.
   */
  topic: string[];

  /**
   * The event's data payload as emitted by the contract. The shape depends
   * entirely on the emitting contract and event type; callers must narrow this
   * with a type guard or cast after inspecting `topic` to determine the event
   * kind.
   */
  value: unknown;
}

export interface EventSource {
  getEvents(
    cursor: string | undefined,
  ): Promise<{ events: RawContractEvent[]; nextCursor: string }>;
}

export interface RpcEventSourceOptions {
  rpcUrl: string;
  networkPassphrase: string;
  contractIds: string[];
  // Soroban RPC requires a starting ledger for the very first (cursor-less)
  // call; callers should pass a recent ledger they know is within the RPC's
  // retention window (commonly ~24h / 17,280 ledgers). Left undefined, the
  // first cursor-less getEvents call throws a descriptive error rather than
  // falling back to ledger 0, which real RPC nodes reject.
  startLedger?: number;
  // Optional timeout in milliseconds for the RPC getEvents call.
  // If the call takes longer than this, it will be rejected.
  // Left undefined, no timeout is applied (relies on SDK's default).
  timeoutMs?: number;
  /**
   * Optional topic filters passed through to Soroban RPC `getEvents`. Each
   * filter is an array of 1-4 topic segments (base64 XDR `ScVal` strings),
   * where `*` matches any single segment. Events matching any filter are
   * returned. Left undefined, all topics are returned.
   */
  topics?: string[][];
  /**
   * Which event types to request: `contract` (default), `system`,
   * `diagnostic`, or `all` (no type restriction).
   */
  eventType?: RpcEventType;
}

export type RpcEventType = 'contract' | 'system' | 'diagnostic' | 'all';

const EVENT_TYPES: readonly RpcEventType[] = ['contract', 'system', 'diagnostic', 'all'];

// Real Soroban RPC request/response shapes vary slightly by SDK minor version and
// require live network access to validate, so this class is intentionally kept out
// of the unit test suite (EventSource above is the seam the rest of the package
// depends on instead) and only needs to compile and behave reasonably. Request/
// response types are derived structurally from `server.getEvents` itself rather
// than naming the SDK's exported type, so this keeps compiling across minor
// SDK versions that rename or relocate that type.
type GetEventsRequest = Parameters<rpc.Server['getEvents']>[0];
type GetEventsResponse = Awaited<ReturnType<rpc.Server['getEvents']>>;

export class RpcEventSource implements EventSource {
  private readonly options: RpcEventSourceOptions;
  private server: rpc.Server | undefined;

  constructor(options: RpcEventSourceOptions) {
    if (options.contractIds.length === 0) {
      throw new Error(
        'horizon-listener: RpcEventSource requires at least one contract ID (contractIds array cannot be empty)',
      );
    }
    if (options.topics !== undefined) {
      if (!Array.isArray(options.topics)) {
        throw new Error('horizon-listener: RpcEventSource `topics` must be an array of topic filters');
      }
      options.topics.forEach((filter, i) => {
        if (
          !Array.isArray(filter) ||
          filter.length === 0 ||
          filter.length > 4 ||
          !filter.every((segment) => typeof segment === 'string' && segment.length > 0)
        ) {
          throw new Error(
            `horizon-listener: RpcEventSource invalid topic filter at index ${i} ` +
              '(expected 1-4 non-empty string segments; use "*" as a wildcard)',
          );
        }
      });
    }
    if (options.eventType !== undefined && !EVENT_TYPES.includes(options.eventType)) {
      throw new Error(
        `horizon-listener: RpcEventSource invalid eventType "${String(options.eventType)}" ` +
          `(expected one of ${EVENT_TYPES.join(', ')})`,
      );
    }
    this.options = options;
  }

  /** Builds the `filters` array sent with every getEvents request. */
  buildFilters(): Record<string, unknown>[] {
    const eventType = this.options.eventType ?? 'contract';
    const filter: Record<string, unknown> = { contractIds: this.options.contractIds };
    if (eventType !== 'all') filter.type = eventType;
    if (this.options.topics && this.options.topics.length > 0) {
      filter.topics = this.options.topics;
    }
    return [filter];
  }

  private getServer(): rpc.Server {
    if (!this.server) {
      this.server = new rpc.Server(this.options.rpcUrl, {
        allowHttp: this.options.rpcUrl.startsWith('http://'),
      });
    }
    return this.server;
  }

  async getEvents(
    cursor: string | undefined,
  ): Promise<{ events: RawContractEvent[]; nextCursor: string }> {
    if (!cursor && this.options.startLedger == null) {
      throw new Error(
        'horizon-listener: RpcEventSource requires `startLedger` for the first cursor-less ' +
          "getEvents call. Pass a recent ledger within the RPC node's event retention window " +
          '(commonly ~24h / 17,280 ledgers); see the horizon-listener README.',
      );
    }

    const server = this.getServer();

    const request = (
      cursor
        ? {
            cursor,
            filters: this.buildFilters(),
          }
        : {
            startLedger: this.options.startLedger,
            filters: this.buildFilters(),
          }
    ) as GetEventsRequest;

    const getEventsPromise = server.getEvents(request);

    const response: GetEventsResponse = this.options.timeoutMs
      ? await Promise.race([
          getEventsPromise,
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error(`RPC getEvents timeout after ${this.options.timeoutMs}ms`)), this.options.timeoutMs)
          ),
        ])
      : await getEventsPromise;

    const rawEvents = (response as unknown as { events?: unknown[] }).events ?? [];

    const events: RawContractEvent[] = rawEvents.map((rawEvent) => {
      const event = rawEvent as {
        id: string;
        contractId: string;
        ledger: number;
        topic?: unknown[];
        value: unknown;
      };
      return {
        id: event.id,
        contractId: event.contractId,
        ledger: event.ledger,
        topic: (event.topic ?? []).map((topicItem) => String(topicItem)),
        value: event.value,
      };
    });

    const responseCursor = (response as unknown as { cursor?: string }).cursor;
    const nextCursor =
      responseCursor ?? (events.length > 0 ? events[events.length - 1].id : (cursor ?? ''));

    return { events, nextCursor };
  }
}
