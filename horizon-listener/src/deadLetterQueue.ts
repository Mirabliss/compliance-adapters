/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import * as fs from 'fs';
import * as path from 'path';
import type { RawContractEvent } from './eventSource';

/** A failed event captured together with the error that caused the failure. */
export interface DeadLetterEvent {
  event: RawContractEvent;
  error: { message: string; stack?: string };
  /** ISO-8601 time at which the event was enqueued. */
  timestamp: string;
}

export interface DeadLetterQueue {
  /** Suitable as (or from within) `onEventFailure`. */
  enqueue(event: RawContractEvent, error: unknown): Promise<void>;
  /** Returns a copy of all stored entries in insertion order. */
  getAll(): DeadLetterEvent[];
  /** Removes the first entry for `eventId`; resolves `false` if none exists. */
  remove(eventId: string): Promise<boolean>;
  clear(): Promise<void>;
}

function toEntry(event: RawContractEvent, error: unknown): DeadLetterEvent {
  const err = error instanceof Error ? error : new Error(String(error));
  return {
    event,
    error: { message: err.message, stack: err.stack },
    timestamp: new Date().toISOString(),
  };
}

export class InMemoryDeadLetterQueue implements DeadLetterQueue {
  protected entries: DeadLetterEvent[] = [];

  async enqueue(event: RawContractEvent, error: unknown): Promise<void> {
    this.entries.push(toEntry(event, error));
  }

  getAll(): DeadLetterEvent[] {
    return [...this.entries];
  }

  async remove(eventId: string): Promise<boolean> {
    const index = this.entries.findIndex((entry) => entry.event.id === eventId);
    if (index === -1) return false;
    this.entries.splice(index, 1);
    return true;
  }

  async clear(): Promise<void> {
    this.entries = [];
  }
}

/**
 * JSON-lines file-backed queue. Existing entries are loaded on construction so
 * they survive restarts. All disk writes are synchronous, so concurrent
 * `enqueue` calls cannot interleave or lose data.
 */
export class FileDeadLetterQueue extends InMemoryDeadLetterQueue {
  constructor(private readonly filePath: string) {
    super();
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    if (fs.existsSync(filePath)) {
      this.entries = fs
        .readFileSync(filePath, 'utf-8')
        .split('\n')
        .filter((line) => line.trim())
        .map((line) => JSON.parse(line) as DeadLetterEvent);
    } else {
      fs.writeFileSync(filePath, '');
    }
  }

  getFilePath(): string {
    return this.filePath;
  }

  override async enqueue(event: RawContractEvent, error: unknown): Promise<void> {
    const entry = toEntry(event, error);
    fs.appendFileSync(this.filePath, JSON.stringify(entry) + '\n');
    this.entries.push(entry);
  }

  override async remove(eventId: string): Promise<boolean> {
    const removed = await super.remove(eventId);
    if (removed) this.persist();
    return removed;
  }

  override async clear(): Promise<void> {
    await super.clear();
    this.persist();
  }

  private persist(): void {
    fs.writeFileSync(
      this.filePath,
      this.entries.map((entry) => JSON.stringify(entry) + '\n').join(''),
    );
  }
}

/** Options for {@link replayDeadLetterQueue}. */
export interface ReplayDeadLetterQueueOptions {
  queue: DeadLetterQueue;
  /** Redeliver one event; must resolve on success and reject on failure. */
  send: (event: RawContractEvent) => Promise<void>;
  /** When true, entries are counted but never removed. */
  dryRun?: boolean;
  /** Maximum entries to attempt (oldest first). Defaults to all. */
  limit?: number;
}

/** Outcome of {@link replayDeadLetterQueue}. */
export interface ReplayDeadLetterQueueResult {
  delivered: number;
  failed: number;
  attempted: number;
}

/**
 * Replays DLQ entries (oldest first) via `send`, removing each entry only
 * after a successful redelivery. Failures remain queued for a later retry.
 */
export async function replayDeadLetterQueue(
  options: ReplayDeadLetterQueueOptions,
): Promise<ReplayDeadLetterQueueResult> {
  const { queue, send, dryRun = false, limit } = options;
  const entries = queue.getAll().slice(0, limit ?? Number.MAX_SAFE_INTEGER);
  let delivered = 0;
  let failed = 0;
  for (const entry of entries) {
    try {
      await send(entry.event);
      delivered++;
      if (!dryRun) await queue.remove(entry.event.id);
    } catch {
      failed++;
    }
  }
  return { delivered, failed, attempted: entries.length };
}
