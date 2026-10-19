/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Keypair } from '@stellar/stellar-sdk';
import { syncSanctionsToDenylist, DenylistWriter, ProviderResultCache } from '../src/sync';
import { CsvSanctionsProvider } from '../src/csvProvider';
import { MockSanctionsProvider } from '../src/mockProvider';
import { RestSanctionsProvider } from '../src/restProvider';
import { SanctionsProvider } from '../src/SanctionsProvider';

const CANONICAL = Keypair.random().publicKey();
const LOWERCASE = CANONICAL.toLowerCase();
const PADDED = `  ${CANONICAL}\t`;
const MIXED = ` ${CANONICAL.slice(0, 25).toLowerCase()}${CANONICAL.slice(25)} `;

function makeWriter(): DenylistWriter & { addToDenylist: jest.Mock } {
  return { addToDenylist: jest.fn().mockResolvedValue({ hash: 'hash' }) };
}

describe('address normalization at ingestion boundaries', () => {
  describe('syncSanctionsToDenylist', () => {
    it('maps mixed-case and padded input to one canonical address', async () => {
      const checkAddress = jest.fn().mockResolvedValue({ flagged: true, source: 'src' });
      const provider: SanctionsProvider = { checkAddress };
      const writer = makeWriter();

      const result = await syncSanctionsToDenylist({
        provider,
        addresses: [CANONICAL, LOWERCASE, PADDED, MIXED],
        writer,
      });

      expect(checkAddress).toHaveBeenCalledTimes(1);
      expect(checkAddress).toHaveBeenCalledWith(CANONICAL);
      expect(result.flagged).toEqual([CANONICAL]);
      expect(result.written).toEqual([CANONICAL]);
      expect(result.invalid).toEqual([]);
      expect(writer.addToDenylist).toHaveBeenCalledTimes(1);
      expect(writer.addToDenylist).toHaveBeenCalledWith(CANONICAL);
    });

    it('uses the normalized form as the cache key', async () => {
      const checkAddress = jest.fn().mockResolvedValue({ flagged: false, source: 'src' });
      const cache = new ProviderResultCache();

      await syncSanctionsToDenylist({
        provider: { checkAddress },
        addresses: [PADDED],
        writer: makeWriter(),
        cache,
      });

      expect(cache.get(CANONICAL)).toEqual({ flagged: false, source: 'src' });
      expect(cache.get(PADDED)).toBeUndefined();
    });

    it('treats a padded currentDenylist entry as already present', async () => {
      const provider: SanctionsProvider = {
        checkAddress: jest.fn().mockResolvedValue({ flagged: true, source: 'src' }),
      };
      const writer = makeWriter();

      const result = await syncSanctionsToDenylist({
        provider,
        addresses: [LOWERCASE],
        writer,
        currentDenylist: [PADDED],
      });

      expect(result.flagged).toEqual([CANONICAL]);
      expect(writer.addToDenylist).not.toHaveBeenCalled();
    });

    it('still reports genuinely malformed input as invalid, verbatim', async () => {
      const result = await syncSanctionsToDenylist({
        provider: { checkAddress: jest.fn() },
        addresses: ['  not-an-address  '],
        writer: makeWriter(),
      });

      expect(result.invalid).toEqual(['  not-an-address  ']);
    });
  });

  describe('CsvSanctionsProvider', () => {
    function writeCsv(rows: string): string {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'normalize-csv-'));
      const file = path.join(dir, 'addresses.csv');
      fs.writeFileSync(file, `address,source\n${rows}`);
      return file;
    }

    it('flags a lowercase CSV row when queried with any spelling', async () => {
      const provider = new CsvSanctionsProvider(writeCsv(`${LOWERCASE},list-a\n`));

      for (const query of [CANONICAL, LOWERCASE, PADDED, MIXED]) {
        const result = await provider.checkAddress(query);
        expect(result).toEqual({ flagged: true, source: 'list-a' });
      }
    });

    it('aggregates rows that differ only in case/padding under one address', async () => {
      const provider = new CsvSanctionsProvider(
        writeCsv(`${CANONICAL},list-a\n${LOWERCASE},list-b\n`),
      );

      const result = await provider.checkAddress(CANONICAL);
      expect(result.source).toBe('list-a,list-b');
    });
  });

  describe('MockSanctionsProvider', () => {
    it('matches regardless of the spelling of the configured or queried address', async () => {
      const fromArray = new MockSanctionsProvider({ flaggedAddresses: [LOWERCASE] });
      const fromObject = new MockSanctionsProvider({ flaggedAddresses: { [PADDED]: 'src-x' } });

      expect((await fromArray.checkAddress(MIXED)).flagged).toBe(true);
      expect(await fromObject.checkAddress(CANONICAL)).toEqual({ flagged: true, source: 'src-x' });
    });
  });

  describe('RestSanctionsProvider', () => {
    it('queries the API with the canonical address', async () => {
      const fetchImpl = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ is_flagged: false, lists: [] }),
      });
      const provider = new RestSanctionsProvider({
        apiBaseUrl: 'https://api.example.com',
        apiKey: 'key',
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });

      await provider.checkAddress(PADDED);
      await provider.checkAddress(LOWERCASE);

      const urls = fetchImpl.mock.calls.map((call) => call[0]);
      expect(urls).toEqual([
        `https://api.example.com/check?address=${CANONICAL}`,
        `https://api.example.com/check?address=${CANONICAL}`,
      ]);
    });
  });
});
