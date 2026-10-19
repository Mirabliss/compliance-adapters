/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/* =========================================================================
 * WARNING: PLACEHOLDER MOCK DATA — DEVELOPMENT/TESTING ONLY
 *
 * This file is a placeholder mock for development and testing ONLY. It
 * contains NO real sanctions data and must NEVER be used as a real
 * compliance data source in production.
 * ========================================================================= */

import { SanctionsProvider } from './SanctionsProvider';
import { StrKey } from '@stellar/stellar-sdk';
import { normalizeStellarAddress } from '@compliance-adapters/shared';
import { type Logger, consoleLogger } from '@compliance-adapters/logger';
import * as fs from 'fs';

const CSV_SOURCE = 'csv-watchlist-v1';

export interface CsvSanctionsProviderOptions {
  /**
   * Logger used to report non-fatal load problems (missing file, invalid rows,
   * read failures). Defaults to {@link consoleLogger} so standalone use still
   * surfaces warnings. Pass `noopLogger` or a custom `Logger` to silence or
   * redirect this output when embedding the provider programmatically.
   */
  logger?: Logger;
}

/**
 * Minimal RFC 4180 CSV parser: handles quoted fields (with embedded commas,
 * newlines and doubled-quote escapes), CRLF/LF line endings and a leading
 * UTF-8 BOM. Returns one string[] per record; blank lines yield `['']` so
 * record indexes stay aligned with line numbers.
 */
export function parseCsv(content: string): string[][] {
  const text = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

export class CsvSanctionsProvider implements SanctionsProvider {
  private flaggedAddresses: Map<string, string[]> = new Map();
  private readonly logger: Logger;

  constructor(
    private csvPath: string,
    options: CsvSanctionsProviderOptions = {},
  ) {
    this.logger = options.logger ?? consoleLogger;
    this.loadCsv();
  }

  private loadCsv(): void {
    try {
      if (!fs.existsSync(this.csvPath)) {
        this.logger.warn(
          `sanctions-oracle: CSV file not found at path: ${this.csvPath}, no addresses will be flagged`,
        );
        return;
      }

      const rows = parseCsv(fs.readFileSync(this.csvPath, 'utf-8'));

      // Skip header row
      for (let i = 1; i < rows.length; i++) {
        const fields = rows[i];
        if (fields.length === 1 && fields[0].trim() === '') continue;

        const address = normalizeStellarAddress(fields[0]);
        if (!StrKey.isValidEd25519PublicKey(address)) {
          this.logger.warn(
            `sanctions-oracle: skipping invalid address at line ${i + 1} of ${this.csvPath}: "${address}" is not a valid Stellar G... address`,
          );
          continue;
        }
        const source = fields[1]?.trim() || CSV_SOURCE;

        const existing = this.flaggedAddresses.get(address);
        if (!existing) {
          this.flaggedAddresses.set(address, [source]);
        } else if (existing.includes(source)) {
          this.logger.warn(
            `sanctions-oracle: address ${address} appears more than once with source "${source}" at line ${i + 1} of ${this.csvPath}; the duplicate row was ignored`,
          );
        } else {
          existing.push(source);
          this.logger.warn(
            `sanctions-oracle: address ${address} appears more than once at line ${i + 1} of ${this.csvPath}; aggregating source "${source}" with existing sources`,
          );
        }
      }
    } catch (error) {
      this.logger.warn(
        `sanctions-oracle: Failed to load CSV from ${this.csvPath}: ${error instanceof Error ? error.message : String(error)}, no addresses will be flagged`,
      );
    }
  }

  async checkAddress(address: string): Promise<{ flagged: boolean; source: string }> {
    const sources = this.flaggedAddresses.get(normalizeStellarAddress(address));
    if (sources && sources.length > 0) {
      return { flagged: true, source: sources.join(',') };
    }
    return { flagged: false, source: CSV_SOURCE };
  }
}
