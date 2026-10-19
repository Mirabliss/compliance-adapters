/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { Keypair } from '@stellar/stellar-sdk';
import { syncSanctionsToDenylist, DenylistWriter, AuditLogEntry } from '../src/sync';
import { InMemoryCheckpointStore } from '../src/checkpoint';
import { SanctionsProvider } from '../src/SanctionsProvider';

const STILL_FLAGGED = Keypair.random().publicKey();
const CLEARED = Keypair.random().publicKey();
const CLEARED_2 = Keypair.random().publicKey();
const NEW_FLAGGED = Keypair.random().publicKey();

/** Provider that flags only the given addresses, tagging results with `source`. */
function makeProvider(flagged: string[], source = 'ofac-sdn'): SanctionsProvider {
  return {
    checkAddress: jest.fn(async (address: string) => ({
      flagged: flagged.includes(address),
      source,
    })),
  };
}

/** In-memory denylist standing in for the contract, with an audit trail. */
function makeChain(initial: string[]) {
  const denylist = new Set(initial);
  const audit: AuditLogEntry[] = [];
  const writer: DenylistWriter & {
    addToDenylist: jest.Mock;
    removeFromDenylistWithSource: jest.Mock;
  } = {
    addToDenylist: jest.fn(async (address: string) => {
      denylist.add(address);
      return { hash: `add-${address.slice(0, 4)}` };
    }),
    removeFromDenylistWithSource: jest.fn(async (address: string, source: string) => {
      denylist.delete(address);
      const entry: AuditLogEntry = {
        address,
        action: 'remove',
        timestamp: new Date().toISOString(),
        source,
        txHash: `rm-${address.slice(0, 4)}`,
      };
      audit.push(entry);
      return { hash: entry.txHash, auditLog: entry };
    }),
  };
  return { denylist, audit, writer };
}

describe('syncSanctionsToDenylist reconcile mode', () => {
  it('does not remove anything when reconcile is not enabled', async () => {
    const { writer, denylist } = makeChain([STILL_FLAGGED, CLEARED]);

    const result = await syncSanctionsToDenylist({
      provider: makeProvider([STILL_FLAGGED]),
      addresses: [STILL_FLAGGED, CLEARED],
      writer,
      currentDenylist: [STILL_FLAGGED, CLEARED],
    });

    expect(writer.removeFromDenylistWithSource).not.toHaveBeenCalled();
    expect(denylist.has(CLEARED)).toBe(true);
    expect(result.removed).toBeUndefined();
    expect(result.plannedRemovals).toBeUndefined();
  });

  it('removes denylist addresses the provider has cleared, even if not in `addresses`', async () => {
    const { writer, denylist } = makeChain([STILL_FLAGGED, CLEARED, CLEARED_2]);

    const result = await syncSanctionsToDenylist({
      provider: makeProvider([STILL_FLAGGED]),
      addresses: [],
      writer,
      currentDenylist: [STILL_FLAGGED, CLEARED, CLEARED_2],
      reconcile: true,
    });

    expect([...denylist]).toEqual([STILL_FLAGGED]);
    expect(result.removed?.sort()).toEqual([CLEARED, CLEARED_2].sort());
    expect(result.failedRemovals).toEqual([]);
    expect(writer.addToDenylist).not.toHaveBeenCalled();
  });

  it('adds new flagged addresses and removes cleared ones in the same run', async () => {
    const { writer, denylist } = makeChain([CLEARED]);

    const result = await syncSanctionsToDenylist({
      provider: makeProvider([NEW_FLAGGED]),
      addresses: [NEW_FLAGGED],
      writer,
      currentDenylist: [CLEARED],
      reconcile: true,
    });

    expect(result.written).toEqual([NEW_FLAGGED]);
    expect(result.removed).toEqual([CLEARED]);
    expect([...denylist]).toEqual([NEW_FLAGGED]);
  });

  it('audit-logs each removal with the clearing provider source', async () => {
    const { writer, audit } = makeChain([CLEARED]);

    await syncSanctionsToDenylist({
      provider: makeProvider([], 'eu-consolidated'),
      addresses: [],
      writer,
      currentDenylist: [CLEARED],
      reconcile: true,
    });

    expect(writer.removeFromDenylistWithSource).toHaveBeenCalledWith(CLEARED, 'eu-consolidated');
    expect(audit).toEqual([
      expect.objectContaining({ address: CLEARED, action: 'remove', source: 'eu-consolidated' }),
    ]);
  });

  it('dry-run shows the planned removals without calling the writer', async () => {
    const { writer, denylist } = makeChain([STILL_FLAGGED, CLEARED]);

    const result = await syncSanctionsToDenylist({
      provider: makeProvider([STILL_FLAGGED], 'ofac-sdn'),
      addresses: [],
      writer,
      currentDenylist: [STILL_FLAGGED, CLEARED],
      reconcile: true,
      dryRun: true,
    });

    expect(result.dryRun).toBe(true);
    expect(result.plannedRemovals).toEqual([{ address: CLEARED, source: 'ofac-sdn' }]);
    expect(result.removed).toEqual([]);
    expect(writer.removeFromDenylistWithSource).not.toHaveBeenCalled();
    expect(denylist.has(CLEARED)).toBe(true);
  });

  it('never removes an address whose provider check failed', async () => {
    const { writer, denylist } = makeChain([CLEARED]);
    const provider: SanctionsProvider = {
      checkAddress: jest.fn().mockRejectedValue(new Error('provider down')),
    };

    const result = await syncSanctionsToDenylist({
      provider,
      addresses: [],
      writer,
      currentDenylist: [CLEARED],
      reconcile: true,
      retry: { maxAttempts: 1 },
    });

    expect(result.failed).toEqual([CLEARED]);
    expect(result.removed).toEqual([]);
    expect(denylist.has(CLEARED)).toBe(true);
  });

  it('records a failed removal without aborting the other removals', async () => {
    const { writer, denylist } = makeChain([CLEARED, CLEARED_2]);
    writer.removeFromDenylistWithSource.mockImplementationOnce(async () => {
      throw new Error('tx failed');
    });

    const result = await syncSanctionsToDenylist({
      provider: makeProvider([]),
      addresses: [],
      writer,
      currentDenylist: [CLEARED, CLEARED_2],
      reconcile: true,
      concurrency: 1,
    });

    expect(result.failedRemovals).toHaveLength(1);
    expect(result.failedRemovals?.[0].error).toBe('tx failed');
    expect(result.removed).toHaveLength(1);
    expect(denylist.size).toBe(1);
  });

  it('falls back to removeFromDenylist when the writer has no source-aware variant', async () => {
    const removeFromDenylist = jest.fn().mockResolvedValue({ hash: 'rm' });
    const writer: DenylistWriter = {
      addToDenylist: jest.fn(),
      removeFromDenylist,
    };

    const result = await syncSanctionsToDenylist({
      provider: makeProvider([]),
      addresses: [],
      writer,
      currentDenylist: [CLEARED],
      reconcile: true,
    });

    expect(removeFromDenylist).toHaveBeenCalledWith(CLEARED);
    expect(result.removed).toEqual([CLEARED]);
  });

  it('rejects a live reconcile when the writer cannot remove', async () => {
    const writer: DenylistWriter = { addToDenylist: jest.fn() };

    await expect(
      syncSanctionsToDenylist({
        provider: makeProvider([]),
        addresses: [],
        writer,
        currentDenylist: [CLEARED],
        reconcile: true,
      }),
    ).rejects.toThrow(/removeFromDenylist/);
  });

  it('checkpoints a cleared address only after it is removed', async () => {
    const { writer } = makeChain([CLEARED]);
    const checkpoint = new InMemoryCheckpointStore();

    await syncSanctionsToDenylist({
      provider: makeProvider([]),
      addresses: [],
      writer,
      currentDenylist: [CLEARED],
      reconcile: true,
      checkpoint,
    });
    expect(checkpoint.isComplete(CLEARED)).toBe(true);

    const dryCheckpoint = new InMemoryCheckpointStore();
    await syncSanctionsToDenylist({
      provider: makeProvider([]),
      addresses: [],
      writer,
      currentDenylist: [CLEARED],
      reconcile: true,
      dryRun: true,
      checkpoint: dryCheckpoint,
    });
    expect(dryCheckpoint.isComplete(CLEARED)).toBe(false);
  });

  it('round trip: sync, provider delists an address, reconcile removes it', async () => {
    const { writer, denylist } = makeChain([]);

    // Run 1: the provider flags both addresses; both are written.
    await syncSanctionsToDenylist({
      provider: makeProvider([STILL_FLAGGED, CLEARED]),
      addresses: [STILL_FLAGGED, CLEARED],
      writer,
    });
    expect([...denylist].sort()).toEqual([STILL_FLAGGED, CLEARED].sort());

    // Run 2: the provider delists CLEARED; reconcile removes it from the chain.
    const result = await syncSanctionsToDenylist({
      provider: makeProvider([STILL_FLAGGED]),
      addresses: [STILL_FLAGGED, CLEARED],
      writer,
      currentDenylist: [...denylist],
      reconcile: true,
    });
    expect(result.removed).toEqual([CLEARED]);
    expect([...denylist]).toEqual([STILL_FLAGGED]);
  });
});
