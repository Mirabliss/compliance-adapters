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

import * as fs from 'fs';
import { SanctionsProvider } from './SanctionsProvider';
import { normalizeStellarAddress } from '@compliance-adapters/shared';

const MOCK_SOURCE = 'mock-watchlist-v1';

// Placeholder watchlist entries with NO real-world meaning. They are valid
// Stellar Ed25519 StrKeys (so they survive `StrKey.isValidEd25519PublicKey`
// validation in syncSanctionsToDenylist) generated once with
// `Keypair.random().publicKey()` — regenerate the same way for fresh values.
// Exported so tests can reference a known-flagged address without
// duplicating magic strings across files.
export const MOCK_FLAGGED_ADDRESSES: Record<string, string> = {
  GCDVWDVSFNX43HOAIMRLPHJAQMPRRDZGRUE6DM6IFSV35BBNMGEZ662M: MOCK_SOURCE,
  GD3AQAE6KUU4W4OMO6QU5LC5MA3E2IQETW6LR2BUHSQE4MNQYAZR6WPS: MOCK_SOURCE,
  GCNM7J7L365GEFEN2DBAIDNXHEZDM7SSQAKDEGCRYUL4LS6OU7DTD3D4: MOCK_SOURCE,
  GARQCALYBJTXSA4CLTI2CTIT2F777ON3KSSYHIIBRZWGTQ2LUFXE56C2: MOCK_SOURCE,
};

export interface MockSanctionsProviderOptions {
  /**
   * Custom flagged addresses, either loaded from a JSON file or passed
   * directly. If omitted, uses MOCK_FLAGGED_ADDRESSES.
   * JSON file format: { "address": "source" } or ["address", "address", ...]
   * If an array is provided, all addresses will use MOCK_SOURCE as the source.
   */
  flaggedAddresses?: Record<string, string> | string[] | string;
}

export class MockSanctionsProvider implements SanctionsProvider {
  private flaggedAddresses: Record<string, string>;

  /**
   * @param options When `options.flaggedAddresses` is a file path, the file is
   * read synchronously, which blocks the event loop for the duration of the
   * read. This is only safe to use at startup (e.g. building module-level
   * config); prefer {@link MockSanctionsProvider.fromFile} inside a request
   * path or anywhere else the blocking read would be a problem.
   */
  constructor(options?: MockSanctionsProviderOptions) {
    this.flaggedAddresses = MockSanctionsProvider.loadFlaggedAddressesSync(options);
  }

  /**
   * Async equivalent of the file-path constructor form: reads
   * `flaggedAddresses` (when it's a file path) with `fs.promises.readFile`
   * instead of blocking the event loop. Non-file-path options
   * (object/array/omitted) behave identically to the constructor and don't
   * need this — use `new MockSanctionsProvider(options)` for those.
   */
  static async fromFile(options?: MockSanctionsProviderOptions): Promise<MockSanctionsProvider> {
    const provider = new MockSanctionsProvider();
    provider.flaggedAddresses = await MockSanctionsProvider.loadFlaggedAddressesAsync(options);
    return provider;
  }

  private static loadFlaggedAddressesSync(
    options?: MockSanctionsProviderOptions,
  ): Record<string, string> {
    if (!options?.flaggedAddresses) {
      return MOCK_FLAGGED_ADDRESSES;
    }

    const flaggedAddresses = options.flaggedAddresses;

    // Handle file path (string)
    if (typeof flaggedAddresses === 'string') {
      try {
        const fileContent = fs.readFileSync(flaggedAddresses, 'utf8');
        const parsed = JSON.parse(fileContent);
        return MockSanctionsProvider.normalizeAddresses(parsed);
      } catch (error) {
        throw new Error(`Failed to load flagged addresses from file ${flaggedAddresses}: ${error}`);
      }
    }

    // Handle direct object or array
    return MockSanctionsProvider.normalizeAddresses(flaggedAddresses);
  }

  private static async loadFlaggedAddressesAsync(
    options?: MockSanctionsProviderOptions,
  ): Promise<Record<string, string>> {
    if (!options?.flaggedAddresses) {
      return MOCK_FLAGGED_ADDRESSES;
    }

    const flaggedAddresses = options.flaggedAddresses;

    // Handle file path (string)
    if (typeof flaggedAddresses === 'string') {
      try {
        const fileContent = await fs.promises.readFile(flaggedAddresses, 'utf8');
        const parsed = JSON.parse(fileContent);
        return MockSanctionsProvider.normalizeAddresses(parsed);
      } catch (error) {
        throw new Error(`Failed to load flagged addresses from file ${flaggedAddresses}: ${error}`);
      }
    }

    // Handle direct object or array
    return MockSanctionsProvider.normalizeAddresses(flaggedAddresses);
  }

  private static normalizeAddresses(
    data: Record<string, string> | string[],
  ): Record<string, string> {
    // An object keyed by address: normalize each key
    if (typeof data === 'object' && !Array.isArray(data)) {
      const result: Record<string, string> = {};
      for (const [address, source] of Object.entries(data as Record<string, string>)) {
        result[normalizeStellarAddress(address)] = source;
      }
      return result;
    }

    // If it's an array, convert to object with MOCK_SOURCE as value
    if (Array.isArray(data)) {
      const result: Record<string, string> = {};
      for (const address of data) {
        result[normalizeStellarAddress(address)] = MOCK_SOURCE;
      }
      return result;
    }

    throw new Error('Flagged addresses must be an object or array');
  }

  async checkAddress(address: string): Promise<{ flagged: boolean; source: string }> {
    const source = this.flaggedAddresses[normalizeStellarAddress(address)];
    if (source) {
      return { flagged: true, source };
    }
    return { flagged: false, source: MOCK_SOURCE };
  }
}
