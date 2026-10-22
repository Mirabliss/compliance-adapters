/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import * as fs from 'fs';
import type { AuditLogEntry, AuditLogger } from './sync';

export interface JsonlAuditLoggerOptions {
  /** fsync the file after every line for durability across power loss. Defaults to false. */
  fsync?: boolean;
}

/**
 * Creates an {@link AuditLogger} that appends one JSON line per audit event to
 * `path` (opened in append-only mode). Each line is the serialized entry,
 * including its ISO 8601 `timestamp`. Writes are serialized through a promise
 * chain so concurrent calls never interleave partial lines.
 */
export function createJsonlAuditLogger(
  path: string,
  options: JsonlAuditLoggerOptions = {},
): AuditLogger {
  let queue: Promise<void> = Promise.resolve();

  const append = async (line: string): Promise<void> => {
    const handle = await fs.promises.open(path, 'a');
    try {
      await handle.write(line);
      if (options.fsync) await handle.sync();
    } finally {
      await handle.close();
    }
  };

  return (entry: AuditLogEntry): Promise<void> => {
    const line = `${JSON.stringify(entry)}\n`;
    const write = queue.then(() => append(line));
    // Keep the chain alive after a failed write; the caller still sees the error.
    queue = write.catch(() => undefined);
    return write;
  };
}
