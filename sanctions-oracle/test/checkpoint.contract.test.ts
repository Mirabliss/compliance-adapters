/// <reference types="jest" />

import { promises as fs } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CheckpointStore,
  FileCheckpointStore,
  RedisCheckpointStore,
  CheckpointRedisLike,
} from '../src/checkpoint';

const FIRST = 'GAAAA';
const SECOND = 'GBBBB';

function makeRedis(): jest.Mocked<CheckpointRedisLike> {
  const values = new Map<string, string>();
  return {
    get: jest.fn(async (key) => values.get(key) ?? null),
    set: jest.fn(async (key, value) => {
      values.set(key, value);
      return 'OK';
    }),
    del: jest.fn(async (key) => {
      values.delete(key);
      return 1;
    }),
  };
}

function contract(name: string, create: () => Promise<CheckpointStore> | CheckpointStore): void {
  describe(name, () => {
    it('loads completed addresses, persists new ones, and resets', async () => {
      const store = await create();

      expect(await store.load()).toEqual([]);
      await store.markComplete(FIRST);
      await store.markComplete(FIRST);
      await store.markComplete(SECOND);
      expect((await store.load()).sort()).toEqual([FIRST, SECOND]);

      await store.reset();
      expect(await store.load()).toEqual([]);
    });
  });
}

contract('FileCheckpointStore', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sanctions-checkpoint-'));
  const file = join(directory, 'checkpoint.json');
  return new FileCheckpointStore(file);
});

contract('RedisCheckpointStore', () => new RedisCheckpointStore(makeRedis()));

describe('FileCheckpointStore validation', () => {
  it('rejects malformed checkpoint files', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'sanctions-checkpoint-invalid-'));
    const file = join(directory, 'checkpoint.json');
    await fs.writeFile(file, JSON.stringify({ address: FIRST }), 'utf8');

    await expect(new FileCheckpointStore(file).load()).rejects.toThrow(
      'Checkpoint file must contain a JSON array of strings',
    );
  });
});
