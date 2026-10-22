/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import * as fs from 'fs';
import type { Logger } from '@compliance-adapters/logger';

/**
 * Persistence contract used by resumable sanctions syncs.
 *
 * `load` returns the addresses completed by an earlier run. Implementations
 * should make `markComplete` durable before it resolves.
 */
export interface CheckpointStore {
  load(): string[] | Promise<string[]>;
  markComplete(address: string): void | Promise<void>;
  reset(): void | Promise<void>;
}

/**
 * Legacy checkpoint contract retained for stores written against earlier
 * versions. New stores should implement {@link CheckpointStore}.
 */
export interface SyncCheckpointStore {
  isComplete(address: string): boolean | Promise<boolean>;
  markComplete(address: string): void | Promise<void>;
}

export interface FileCheckpointStoreOptions {
  /** Optional JSON indentation for the checkpoint file. Defaults to 2. */
  spaces?: number;
}

/**
 * JSON-file implementation of {@link CheckpointStore}.
 *
 * A missing file is treated as an empty checkpoint. Writes use a temporary
 * file followed by a rename so a process restart cannot leave a partial JSON
 * document behind.
 */
export class FileCheckpointStore implements CheckpointStore {
  private readonly spaces: number;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly filePath: string,
    options: FileCheckpointStoreOptions = {},
  ) {
    this.spaces = options.spaces ?? 2;
  }

  async load(): Promise<string[]> {
    try {
      const content = await fs.readFile(this.filePath, 'utf8');
      const parsed: unknown = JSON.parse(content);
      if (!Array.isArray(parsed) || !parsed.every((entry) => typeof entry === 'string')) {
        throw new Error(`Checkpoint file must contain a JSON array of strings: ${this.filePath}`);
      }
      return [...new Set(parsed)];
    } catch (error) {
      if (isFileNotFound(error)) return [];
      throw error;
    }
  }

  async markComplete(address: string): Promise<void> {
    await this.enqueue(async () => {
      const completed = new Set(await this.load());
      completed.add(address);
      await this.write([...completed]);
    });
  }

  async reset(): Promise<void> {
    await this.enqueue(() => this.write([]));
  }

  private enqueue(operation: () => Promise<void>): Promise<void> {
    const next = this.writeQueue.then(operation);
    this.writeQueue = next.catch(() => undefined);
    return next;
  }

  private async write(addresses: string[]): Promise<void> {
    await fs.mkdir(dirname(this.filePath), { recursive: true });
    const temporaryPath = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
    try {
      await fs.writeFile(temporaryPath, `${JSON.stringify(addresses, null, this.spaces)}\n`, 'utf8');
      await fs.rename(temporaryPath, this.filePath);
    } catch (error) {
      await fs.rm(temporaryPath, { force: true });
      throw error;
    }
  }
}

/**
 * Minimal Redis client surface required by {@link RedisCheckpointStore}.
 * Both ioredis and node-redis can be adapted to this shape without adding a
 * Redis client dependency to sanctions-oracle.
 */
export interface CheckpointRedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  del(key: string): Promise<unknown>;
}

export interface RedisCheckpointStoreOptions {
  /** Redis key used for the serialized set of completed addresses. */
  key?: string;
}

/**
 * Redis-backed implementation of {@link CheckpointStore}.
 */
export class RedisCheckpointStore implements CheckpointStore {
  private readonly key: string;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly redis: CheckpointRedisLike,
    options: RedisCheckpointStoreOptions = {},
  ) {
    this.key = options.key ?? 'sanctions-oracle:checkpoint';
  }

  async load(): Promise<string[]> {
    const value = await this.redis.get(this.key);
    if (value === null) return [];
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed) || !parsed.every((entry) => typeof entry === 'string')) {
      throw new Error(`Redis checkpoint value must be a JSON array of strings: ${this.key}`);
    }
    return [...new Set(parsed)];
  }

  async markComplete(address: string): Promise<void> {
    const next = this.writeQueue.then(async () => {
      const completed = new Set(await this.load());
      completed.add(address);
      await this.redis.set(this.key, JSON.stringify([...completed]));
    });
    this.writeQueue = next.catch(() => undefined);
    await next;
  }

  async reset(): Promise<void> {
    const next = this.writeQueue.then(() => this.redis.del(this.key).then(() => undefined));
    this.writeQueue = next.catch(() => undefined);
    await next;
  }
}

/**
 * In-memory reference implementation of {@link CheckpointStore}.
 */
export class InMemoryCheckpointStore implements CheckpointStore, SyncCheckpointStore {
  private readonly completed: Set<string>;

  constructor(initiallyComplete: Iterable<string> = []) {
    this.completed = new Set(initiallyComplete);
  }

  load(): string[] {
    return [...this.completed];
  }

  isComplete(address: string): boolean {
    return this.completed.has(address);
  }

  markComplete(address: string): void {
    this.completed.add(address);
  }

  reset(): void {
    this.completed.clear();
  }

  snapshot(): string[] {
    return this.load();
  }
}

/**
 * File-backed {@link SyncCheckpointStore} that persists completed addresses as
 * a JSON array, so a sync can resume after the process is killed.
 *
 * Writes are atomic: the snapshot is written to `<path>.tmp` and then renamed
 * over `path`, so a crash mid-write never leaves a truncated checkpoint. If the
 * existing file can't be parsed anyway (e.g. written by an older, non-atomic
 * version), it is moved aside to `<path>.corrupt-<timestamp>`, a warning is
 * logged, and the store starts fresh instead of crashing the sync.
 */
export class FileCheckpointStore implements SyncCheckpointStore {
  private readonly completed: Set<string>;

  constructor(
    private readonly path: string,
    logger?: Pick<Logger, 'warn'>,
  ) {
    this.completed = new Set(FileCheckpointStore.load(path, logger));
  }

  private static load(path: string, logger?: Pick<Logger, 'warn'>): string[] {
    let raw: string;
    try {
      raw = fs.readFileSync(path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    }
    try {
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === 'string')) {
        throw new Error('checkpoint must be a JSON array of strings');
      }
      return parsed;
    } catch (error) {
      const corruptPath = `${path}.corrupt-${Date.now()}`;
      fs.renameSync(path, corruptPath);
      logger?.warn('sanctions-oracle: checkpoint file is corrupt; starting fresh', {
        path,
        movedTo: corruptPath,
        error: error instanceof Error ? error.message : String(error),
      });
      return [];
    }
  }

  isComplete(address: string): boolean {
    return this.completed.has(address);
  }

  markComplete(address: string): void {
    if (this.completed.has(address)) return;
    this.completed.add(address);
    const tmpPath = `${this.path}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify([...this.completed]));
    fs.renameSync(tmpPath, this.path);
  }

  /** All addresses recorded as complete so far. */
  snapshot(): string[] {
    return [...this.completed];
  }
}
