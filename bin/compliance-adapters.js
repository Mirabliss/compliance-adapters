#!/usr/bin/env node
'use strict';

/**
 * bin/compliance-adapters.js
 *
 * Unified CLI for the compliance-adapters monorepo.
 *
 * Usage:
 *   compliance-adapters <command> [options]
 *
 * Commands:
 *   sync-sanctions   Push flagged addresses into a deployed denylist-gate contract
 *   listen           Poll Soroban RPC for contract events and forward to a webhook
 *   dlq              Inspect and replay the dead-letter queue
 *
 * Run `compliance-adapters <command> --help` for command-specific flags.
 */

const COMMANDS = {
  'sync-sanctions': runSyncSanctions,
  listen: runListen,
  dlq: runDlq,
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const [, , command, ...rest] = process.argv;

if (!command || command === '--help' || command === '-h') {
  printUsage();
  process.exit(0);
}

const handler = COMMANDS[command];
if (!handler) {
  console.error(`Unknown command: "${command}"\n`);
  printUsage();
  process.exit(1);
}

handler(rest).catch((err) => {
  console.error(err.message ?? err);
  process.exitCode = 1;
});

// ---------------------------------------------------------------------------
// Global usage
// ---------------------------------------------------------------------------

function printUsage() {
  console.log(`
compliance-adapters <command> [options]

Commands:
  sync-sanctions   Push flagged addresses into a deployed denylist-gate contract
  listen           Poll Soroban RPC for contract events and forward to a webhook
  dlq              Inspect and replay the dead-letter queue (try: dlq replay --help)

Options:
  --help, -h       Show this help message

Run \`compliance-adapters <command> --help\` for command-specific flags.
`.trim());
}

// ---------------------------------------------------------------------------
// sync-sanctions command
// ---------------------------------------------------------------------------

/**
 * Flags:
 *   --addresses <path>          Path to a JSON array of Stellar addresses to check
 *   --dry-run                   Log what would happen without submitting any transactions
 *   --contract-id <id>          Deployed denylist-gate contract ID
 *   --rpc-url <url>             Soroban RPC endpoint
 *   --network-passphrase <str>  Stellar network passphrase
 *   --secret-key <key>          Source account secret key for signing transactions
 *   --help                      Show this help message
 */
async function runSyncSanctions(argv) {
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`
compliance-adapters sync-sanctions [options]

Push flagged addresses into a deployed denylist-gate contract via Soroban RPC.

Options:
  --addresses <path>          Path to a JSON array of Stellar addresses (required)
  --dry-run                   Print what would be written without submitting transactions
  --contract-id <id>          Deployed denylist-gate contract ID (required unless --dry-run)
  --rpc-url <url>             Soroban RPC endpoint (required unless --dry-run)
  --network-passphrase <str>  Stellar network passphrase (default: testnet)
  --secret-key <key>          Source account secret key (required unless --dry-run)
  --help                      Show this help message
`.trim());
    return;
  }

  const fs = require('fs');
  const args = parseFlags(argv);

  if (!args['addresses']) {
    console.error('Missing required flag: --addresses <path-to-json-array>');
    process.exitCode = 1;
    return;
  }

  const { MockSanctionsProvider, syncSanctionsToDenylist, createRpcDenylistWriter } =
    require('../sanctions-oracle/dist/index.js');
  const { Keypair, Networks } = require('@stellar/stellar-sdk');

  const addresses = JSON.parse(fs.readFileSync(args['addresses'], 'utf8'));
  const provider = new MockSanctionsProvider();
  const dryRun = 'dry-run' in args;
  const networkPassphrase = args['network-passphrase'] ?? Networks.TESTNET;

  if (dryRun) {
    const result = await syncSanctionsToDenylist({
      provider,
      addresses,
      writer: {
        async addToDenylist() {
          throw new Error('addToDenylist must not be called in dry-run mode');
        },
      },
      dryRun: true,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const missingFlags = ['contract-id', 'rpc-url', 'secret-key'].filter((f) => !args[f]);
  if (missingFlags.length > 0) {
    console.error(
      `Missing required flags for live sync: ${missingFlags.map((f) => `--${f}`).join(', ')}`,
      '\n(or pass --dry-run to skip transaction submission)',
    );
    process.exitCode = 1;
    return;
  }

  const writer = createRpcDenylistWriter({
    rpcUrl: args['rpc-url'],
    networkPassphrase,
    contractId: args['contract-id'],
    sourceKeypair: Keypair.fromSecret(args['secret-key']),
  });

  const result = await syncSanctionsToDenylist({ provider, addresses, writer, dryRun: false });
  console.log(JSON.stringify(result, null, 2));
}

// ---------------------------------------------------------------------------
// listen command (#285)
// ---------------------------------------------------------------------------

/**
 * Flags:
 *   --contract-id <id>          Deployed contract ID to filter events for (required, repeatable)
 *   --rpc-url <url>             Soroban RPC endpoint (default: testnet)
 *   --network-passphrase <str>  Stellar network passphrase (default: testnet)
 *   --webhook-url <url>         Webhook to POST events to (required unless --dry-run)
 *   --dry-run                   Print events to stdout instead of sending to a webhook
 *   --start-ledger <n>          Starting ledger for the first poll (default: none)
 *   --poll-interval-ms <n>      Polling interval in milliseconds (default: 5000)
 *   --max-retries <n>           Max consecutive poll failures before exiting (default: 10)
 *   --help                      Show this help message
 */
async function runListen(argv) {
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`
compliance-adapters listen [options]

Poll Soroban RPC for contract events and forward each one to a webhook URL.

Options:
  --contract-id <id>          Contract ID to watch (required; repeat for multiple contracts)
  --rpc-url <url>             Soroban RPC endpoint (default: https://soroban-testnet.stellar.org)
  --network-passphrase <str>  Stellar network passphrase (default: testnet)
  --webhook-url <url>         Webhook endpoint to POST events to (required unless --dry-run)
  --dry-run                   Print events to stdout instead of sending them to a webhook
  --start-ledger <n>          Starting ledger for the very first poll (omit to use cursor-only)
  --poll-interval-ms <n>      Milliseconds between polls (default: 5000)
  --max-retries <n>           Max consecutive failures before the process exits (default: 10)
  --help                      Show this help message

Examples:
  # Dry-run: print events to stdout instead of sending to a webhook
  compliance-adapters listen \\
    --contract-id CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABH4M \\
    --rpc-url https://soroban-testnet.stellar.org \\
    --dry-run \\
    --start-ledger 100000

  # Forward events to a webhook
  compliance-adapters listen \\
    --contract-id CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABH4M \\
    --webhook-url http://localhost:9000/events

  # Multiple contracts
  compliance-adapters listen \\
    --contract-id <denylist-id> \\
    --contract-id <allowlist-id> \\
    --webhook-url https://my-service.example.com/stellar-events
`.trim());
    return;
  }

  const { Networks } = require('@stellar/stellar-sdk');
  const { HorizonListener, RpcEventSource, HttpWebhookSender } =
    require('../horizon-listener/dist/index.js');

  // --contract-id is multi-value; collect all occurrences
  const contractIds = collectRepeatedFlag(argv, '--contract-id');
  const args = parseFlags(argv);

  const rpcUrl = args['rpc-url'] ?? 'https://soroban-testnet.stellar.org';
  const networkPassphrase = args['network-passphrase'] ?? Networks.TESTNET;
  const dryRun = args['dry-run'] === true;
  const webhookUrl = typeof args['webhook-url'] === 'string' ? args['webhook-url'] : null;
  const startLedger = args['start-ledger'] ? parseInt(args['start-ledger'], 10) : undefined;
  const pollIntervalMs = args['poll-interval-ms'] ? parseInt(args['poll-interval-ms'], 10) : 5000;
  const maxRetries = args['max-retries'] ? parseInt(args['max-retries'], 10) : 10;

  if (contractIds.length === 0) {
    console.error('Missing required flag: --contract-id <id>');
    process.exitCode = 1;
    return;
  }

  if (!webhookUrl && !dryRun) {
    console.error('Missing required flag: --webhook-url <url>');
    process.exitCode = 1;
    return;
  }

  const eventSource = new RpcEventSource({
    rpcUrl,
    networkPassphrase,
    contractIds,
    startLedger,
  });

  const webhookSender = dryRun ? null : new HttpWebhookSender({ url: webhookUrl });

  const listener = new HorizonListener({
    eventSource,
    async onEvent(event) {
      console.info('[listen] event received:', JSON.stringify(event));
      if (webhookSender) await webhookSender.send(event);
    },
    pollIntervalMs,
    maxRetries,
    logger: {
      debug: (...a) => console.debug('[listen]', ...a),
      info: (...a) => console.info('[listen]', ...a),
      warn: (...a) => console.warn('[listen]', ...a),
      error: (...a) => console.error('[listen]', ...a),
    },
  });

  // Graceful shutdown on SIGINT / SIGTERM
  process.on('SIGINT', () => {
    console.info('\n[listen] Received SIGINT — stopping listener...');
    listener.stop();
  });
  process.on('SIGTERM', () => {
    console.info('[listen] Received SIGTERM — stopping listener...');
    listener.stop();
  });

  console.info('[listen] Starting Horizon event listener...');
  console.info(`[listen]   contracts:      ${contractIds.join(', ')}`);
  console.info(`[listen]   rpc-url:        ${rpcUrl}`);
  console.info(`[listen]   webhook-url:    ${dryRun ? '(dry-run: events printed only)' : webhookUrl}`);
  console.info(`[listen]   poll-interval:  ${pollIntervalMs}ms`);
  console.info(`[listen]   max-retries:    ${maxRetries}`);
  if (startLedger !== undefined) {
    console.info(`[listen]   start-ledger:   ${startLedger}`);
  }
  console.info('[listen] Press Ctrl+C to stop.\n');

  await listener.start();
  console.info('[listen] Listener stopped.');
}

// ---------------------------------------------------------------------------
// dlq command (#821): replay events from the dead-letter queue
// ---------------------------------------------------------------------------

/**
 * Usage:
 *   compliance-adapters dlq replay --dlq <path> --webhook <url> [--dry-run] [--limit N]
 */
async function runDlq(argv) {
  const [subcommand, ...subRest] = argv;
  if (subcommand !== 'replay' || subRest.includes('--help') || subRest.includes('-h')) {
    console.log(`
compliance-adapters dlq replay [options]

Replay events from the dead-letter queue via the webhook.

Options:
  --dlq <path>      Path to the File DLQ (JSON-lines file) (required)
  --webhook <url>   Webhook endpoint to POST events to (required unless --dry-run)
  --dry-run         Count what would be replayed without sending or removing entries
  --limit <n>       Maximum entries to attempt, oldest first (default: all)
  --help            Show this help message
`.trim());
    if (subcommand !== 'replay') {
      console.error('\nUnknown dlq subcommand: expected "replay"');
      process.exitCode = 1;
    }
    return;
  }

  const args = parseFlags(subRest);
  const dlqPath = typeof args['dlq'] === 'string' ? args['dlq'] : null;
  const webhookUrl = typeof args['webhook'] === 'string' ? args['webhook'] : null;
  const dryRun = args['dry-run'] === true;
  const limit = args['limit'] !== undefined ? parseInt(args['limit'], 10) : undefined;

  if (!dlqPath) {
    console.error('Missing required flag: --dlq <path-to-dlq-file>');
    process.exitCode = 1;
    return;
  }
  if (!webhookUrl && !dryRun) {
    console.error('Missing required flag: --webhook <url> (or pass --dry-run)');
    process.exitCode = 1;
    return;
  }
  if (limit !== undefined && (!Number.isInteger(limit) || limit <= 0)) {
    console.error('Invalid flag: --limit must be a positive integer');
    process.exitCode = 1;
    return;
  }

  // Prefer the built package; fall back to a minimal JSON-lines reader so the
  // CLI works even before `npm run build` has been run.
  let FileDeadLetterQueue;
  let replayDeadLetterQueue;
  try {
    ({ FileDeadLetterQueue, replayDeadLetterQueue } = require('../horizon-listener/dist/index.js'));
  } catch {
    const fs = require('fs');
    FileDeadLetterQueue = class {
      constructor(p) {
        this.filePath = p;
        this.entries = fs.existsSync(p)
          ? fs.readFileSync(p, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
          : [];
      }
      getAll() { return [...this.entries]; }
      async remove(id) {
        const i = this.entries.findIndex((e) => e.event.id === id);
        if (i === -1) return false;
        this.entries.splice(i, 1);
        fs.writeFileSync(this.filePath, this.entries.map((e) => JSON.stringify(e) + '\n').join(''));
        return true;
      }
    };
    replayDeadLetterQueue = async ({ queue, send, dryRun: dr, limit: lim }) => {
      const entries = queue.getAll().slice(0, lim ?? Number.MAX_SAFE_INTEGER);
      let delivered = 0, failed = 0;
      for (const entry of entries) {
        try { await send(entry.event); delivered++; if (!dr) await queue.remove(entry.event.id); }
        catch { failed++; }
      }
      return { delivered, failed, attempted: entries.length };
    };
  }

  const queue = new FileDeadLetterQueue(dlqPath);
  const send = async (event) => {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event }),
    });
    if (!res.ok) throw new Error(`webhook POST failed with status ${res.status}`);
  };

  const result = await replayDeadLetterQueue({ queue, send: dryRun ? async () => {} : send, dryRun, limit });
  console.log(JSON.stringify({ dlq: dlqPath, dryRun, ...result }));
}

// ---------------------------------------------------------------------------
// Argument parsing helpers
// ---------------------------------------------------------------------------

/**
 * Parse a flat argv array into a key→value map.
 * Boolean flags (no following value, or value starts with --) are stored as `true`.
 *
 * @param {string[]} argv
 * @returns {Record<string, string | true>}
 */
function parseFlags(argv) {
  /** @type {Record<string, string | true>} */
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      out[key] = next;
      i++;
    } else {
      out[key] = true;
    }
  }
  return out;
}

/**
 * Collect all values for a flag that may appear multiple times.
 * e.g. `--contract-id A --contract-id B` → ['A', 'B']
 *
 * @param {string[]} argv
 * @param {string} flag  e.g. '--contract-id'
 * @returns {string[]}
 */
function collectRepeatedFlag(argv, flag) {
  const values = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === flag && argv[i + 1] && !argv[i + 1].startsWith('--')) {
      values.push(argv[i + 1]);
      i++;
    }
  }
  return values;
}
