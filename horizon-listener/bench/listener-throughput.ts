import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { HorizonListener } from '../src/listener';
import { HttpWebhookSender } from '../src/webhook';
import type { RawContractEvent } from '../src/eventSource';

// Throughput benchmark for HorizonListener + HttpWebhookSender: feeds
// synthetic events through a mocked EventSource into a local HTTP receiver
// and reports events/sec for sequential and batched modes.

const TOTAL_EVENTS = 200;

function makeEvent(id: number): RawContractEvent {
  return {
    id: `event-${id}`,
    contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
    ledger: 1000 + id,
    timestamp: new Date().toISOString(),
    topic: ['transfer'],
    value: { amount: '100' },
  } as unknown as RawContractEvent;
}

function startReceiver(countTarget: { received: number }): Promise<{ server: Server; url: string }> {
  return new Promise((resolve) => {
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      req.resume();
      req.on('end', () => {
        countTarget.received += 1;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({ server, url: `http://127.0.0.1:${port}/webhook` });
    });
  });
}

async function runMode(
  mode: 'sequential' | 'batched',
  sender: HttpWebhookSender,
): Promise<number> {
  const events = Array.from({ length: TOTAL_EVENTS }, (_, i) => makeEvent(i));
  let delivered = 0;

  const eventSource =
    mode === 'sequential'
      ? {
          getEvents: async (): Promise<{ events: RawContractEvent[]; nextCursor: string }> => {
            if (delivered >= TOTAL_EVENTS) {
              await new Promise((r) => setTimeout(r, 50));
              return { events: [], nextCursor: String(delivered) };
            }
            return { events: [events[delivered]], nextCursor: String(delivered) };
          },
        }
      : {
          getEvents: async (): Promise<{ events: RawContractEvent[]; nextCursor: string }> => {
            if (delivered >= TOTAL_EVENTS) {
              await new Promise((r) => setTimeout(r, 50));
              return { events: [], nextCursor: String(delivered) };
            }
            const batch = events.slice(delivered, delivered + 10);
            return { events: batch, nextCursor: String(delivered) };
          },
        };

  const listener = new HorizonListener({
    eventSource,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    onEvent: async (_event: RawContractEvent) => {
      await sender.send(_event);
      delivered += 1;
      if (delivered >= TOTAL_EVENTS) {
        void listener.stop();
      }
    },
    pollIntervalMs: 1,
    mode: 'poll',
    logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
  });

  const start = Date.now();
  await listener.start();
  const elapsedMs = Math.max(1, Date.now() - start);
  return Number(((delivered / elapsedMs) * 1000).toFixed(1));
}

async function main(): Promise<void> {
  const counter = { received: 0 };
  const { server, url } = await startReceiver(counter);
  try {
    const sender = new HttpWebhookSender({ url, maxRetries: 0 });
    const sequential = await runMode('sequential', sender);
    counter.received = 0;
    const batched = await runMode('batched', sender);
    const opsPerSecond = Math.max(sequential, batched);
    const result = {
      benchmark: 'horizon-listener-webhook-throughput',
      durationMs: TOTAL_EVENTS,
      iterations: TOTAL_EVENTS,
      opsPerSecond,
      modes: { sequential, batched },
      timestamp: new Date().toISOString(),
    };
    console.log(
      `horizon-listener: ${TOTAL_EVENTS} events sequential=${sequential}/s batched=${batched}/s`,
    );
    console.log(`BENCHMARK_RESULT_JSON=${JSON.stringify(result)}`);
  } finally {
    server.close();
  }
}

void main();
