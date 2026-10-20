import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { FileDeadLetterQueue, replayDeadLetterQueue } from '../src/deadLetterQueue';

function makeEvent(id: string) {
  return { id, contractId: 'C', ledger: 1, timestamp: 't', type: 'ev', data: {} } as never;
}

describe('dlq replay (#821)', () => {
  it('removes successes and keeps failures (File DLQ)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dlq-'));
    const file = path.join(dir, 'dlq.jsonl');
    const queue = new FileDeadLetterQueue(file);
    await queue.enqueue(makeEvent('ok-1'), new Error('boom'));
    await queue.enqueue(makeEvent('fail-1'), new Error('boom'));
    await queue.enqueue(makeEvent('ok-2'), new Error('boom'));

    const result = await replayDeadLetterQueue({
      queue,
      send: async (event) => {
        if ((event as { id: string }).id.startsWith('fail')) throw new Error('down');
      },
      limit: 10,
    });

    expect(result).toEqual({ delivered: 2, failed: 1, attempted: 3 });
    expect(queue.getAll().map((e) => e.event.id)).toEqual(['fail-1']);

    const dry = await replayDeadLetterQueue({
      queue,
      send: async () => {},
      dryRun: true,
    });
    expect(dry.attempted).toBe(1);
    expect(queue.getAll()).toHaveLength(1);
  });
});
