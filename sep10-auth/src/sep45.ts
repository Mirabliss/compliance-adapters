/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * SEP-45 (Stellar Web Authentication for Contract Accounts) prototype.
 *
 * SEP-10 authenticates classic accounts (`G...`/`M...`) with a signed
 * `manage_data` transaction. SEP-45 authenticates Soroban contract accounts
 * (`C...`), which cannot sign classic transactions, with Soroban authorization
 * entries for a call to the anchor's `web_auth_verify` contract function.
 *
 * This module is intentionally NOT re-exported from the package index so the
 * SEP-10 surface stays stable. Import it directly:
 *
 * ```ts
 * import { generateContractChallenge, verifyContractChallenge } from 'sep10-auth/dist/sep45';
 * ```
 *
 * See `docs/sep45-design.md` for the flow and the prototype's limits.
 */

import { randomBytes } from 'crypto';
import {
  Address,
  Keypair,
  Networks,
  StrKey,
  authorizeEntry,
  buildAuthorizationEntryPreimage,
  hash,
  xdr,
} from '@stellar/stellar-sdk';
import { assertBareDomain } from './challenge';
import type { VerifyErrorCode } from './verify';

/** Contract function every SEP-45 challenge invokes. */
export const WEB_AUTH_FUNCTION_NAME = 'web_auth_verify';

export interface GenerateContractChallengeOptions {
  /** Contract ID (`C...`) of the anchor's web-auth contract. */
  webAuthContractId: string;
  /**
   * Last ledger for which the entries are valid (`signatureExpirationLedger`).
   * The caller derives it from the current ledger (e.g. from Soroban RPC) plus
   * the desired lifetime.
   */
  validUntilLedger: number;
  homeDomain?: string;
  webAuthDomain?: string;
  networkPassphrase?: string;
}

/** The result of {@link generateContractChallenge}. */
export interface GeneratedContractChallenge {
  /**
   * Base64 XDR `SorobanAuthorizationEntry` values: the server-signed entry and
   * the client's unsigned entry. The client signs its own entry and returns both.
   */
  authorizationEntries: string[];
  /** Random nonce embedded in the `nonce` argument; track it to prevent replay. */
  nonce: string;
  networkPassphrase: string;
  validUntilLedger: number;
}

export interface VerifyContractChallengeOptions {
  webAuthContractId: string;
  serverAccountId: string;
  homeDomains: string | string[];
  webAuthDomain: string | string[];
  networkPassphrase?: string;
  /** Current ledger sequence; when set, entries whose expiration ledger has passed are rejected. */
  currentLedger?: number;
  /**
   * Validates the client entry's signature. A contract account's signature is
   * checked by its `__check_auth` implementation, so this is typically backed by
   * a Soroban RPC simulation of the `web_auth_verify` call with the signed
   * entries. Required: without it a forged client entry could not be detected.
   */
  verifyClientAuthorization: (
    clientEntry: xdr.SorobanAuthorizationEntry,
    allEntries: xdr.SorobanAuthorizationEntry[],
  ) => boolean | Promise<boolean>;
}

/** The result of {@link verifyContractChallenge}. */
export interface VerifyContractChallengeResult {
  valid: boolean;
  /** The authenticated contract account (`C...`), or `''` when `valid` is `false`. */
  address: string;
  /** The challenge nonce, present only when `valid` is `true`. */
  nonce?: string;
  /** The matched `home_domain`, present only when `valid` is `true`. */
  homeDomain?: string;
  error?: string;
  errorCode?: VerifyErrorCode;
}

class ContractChallengeError extends Error {
  constructor(
    readonly code: VerifyErrorCode,
    message: string,
  ) {
    super(message);
  }
}

const DEFAULT_HOME_DOMAIN = 'localhost:3000';

function buildArgsMap(args: Record<string, string>): xdr.ScVal {
  // Soroban requires map keys in sorted order; all keys here are ASCII.
  const entries = Object.keys(args)
    .sort()
    .map(
      (key) =>
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvString(key),
          val: xdr.ScVal.scvString(args[key]),
        }),
    );
  return xdr.ScVal.scvMap(entries);
}

function randomInt64(): xdr.Int64 {
  const value = BigInt.asIntN(64, BigInt(`0x${randomBytes(8).toString('hex')}`));
  return xdr.Int64.fromString(value.toString());
}

function buildEntry(
  account: string,
  webAuthContractId: string,
  argsMap: xdr.ScVal,
  validUntilLedger: number,
): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: new Address(account).toScAddress(),
        nonce: randomInt64(),
        signatureExpirationLedger: validUntilLedger,
        signature: xdr.ScVal.scvVec([]),
      }),
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: new Address(webAuthContractId).toScAddress(),
          functionName: WEB_AUTH_FUNCTION_NAME,
          args: [argsMap],
        }),
      ),
      subInvocations: [],
    }),
  });
}

/**
 * Builds a SEP-45 challenge for a contract account: a server-signed
 * authorization entry plus an unsigned entry for `clientContractId`, both for
 * `web_auth_verify(args)`. Unlike {@link generateChallenge} it is async because
 * signing an authorization entry is.
 *
 * Throws on invalid input (non-`C...` client, non-`C...` web-auth contract,
 * non-bare domains, unsignable server keypair), mirroring `generateChallenge`.
 */
export async function generateContractChallenge(
  clientContractId: string,
  serverKeypair: Keypair,
  options: GenerateContractChallengeOptions,
): Promise<GeneratedContractChallenge> {
  if (!serverKeypair.canSign()) {
    throw new Error('sep10-auth: serverKeypair cannot sign — provide a keypair with a secret key');
  }
  if (!StrKey.isValidContract(clientContractId)) {
    throw new Error(`sep10-auth: clientContractId must be a contract address (C...), got ${clientContractId}`);
  }
  if (!StrKey.isValidContract(options.webAuthContractId)) {
    throw new Error(
      `sep10-auth: webAuthContractId must be a contract address (C...), got ${options.webAuthContractId}`,
    );
  }
  if (!Number.isInteger(options.validUntilLedger) || options.validUntilLedger <= 0) {
    throw new Error('sep10-auth: validUntilLedger must be a positive integer ledger sequence');
  }

  const homeDomain = options.homeDomain ?? DEFAULT_HOME_DOMAIN;
  const webAuthDomain = options.webAuthDomain ?? homeDomain;
  assertBareDomain('homeDomain', homeDomain);
  assertBareDomain('webAuthDomain', webAuthDomain);

  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET;
  const nonce = randomBytes(16).toString('hex');
  const argsMap = buildArgsMap({
    account: clientContractId,
    home_domain: homeDomain,
    nonce,
    web_auth_domain: webAuthDomain,
    web_auth_domain_account: serverKeypair.publicKey(),
  });

  const serverEntry = await authorizeEntry(
    buildEntry(serverKeypair.publicKey(), options.webAuthContractId, argsMap, options.validUntilLedger),
    serverKeypair,
    options.validUntilLedger,
    networkPassphrase,
  );
  const clientEntry = buildEntry(
    clientContractId,
    options.webAuthContractId,
    argsMap,
    options.validUntilLedger,
  );

  return {
    authorizationEntries: [serverEntry.toXDR('base64'), clientEntry.toXDR('base64')],
    nonce,
    networkPassphrase,
    validUntilLedger: options.validUntilLedger,
  };
}

function addressCredentials(entry: xdr.SorobanAuthorizationEntry): xdr.SorobanAddressCredentials {
  const credentials = entry.credentials();
  if (
    credentials.switch().value !==
    xdr.SorobanCredentialsType.sorobanCredentialsAddress().value
  ) {
    throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: entry does not use address credentials');
  }
  return credentials.address();
}

function entryAddress(entry: xdr.SorobanAuthorizationEntry): string {
  return Address.fromScAddress(addressCredentials(entry).address()).toString();
}

/** Extracts the `Map<String,String>` argument after checking the call target. */
function readArgs(
  entry: xdr.SorobanAuthorizationEntry,
  webAuthContractId: string,
): { args: Record<string, string>; raw: string } {
  const invocation = entry.rootInvocation();
  if (invocation.subInvocations().length !== 0) {
    throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: unexpected sub-invocations');
  }
  const fn = invocation.function();
  if (
    fn.switch().value !==
    xdr.SorobanAuthorizedFunctionType.sorobanAuthorizedFunctionTypeContractFn().value
  ) {
    throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: entry is not a contract invocation');
  }
  const call = fn.contractFn();
  if (Address.fromScAddress(call.contractAddress()).toString() !== webAuthContractId) {
    throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: wrong web auth contract');
  }
  if (call.functionName().toString() !== WEB_AUTH_FUNCTION_NAME) {
    throw new ContractChallengeError('INVALID_CHALLENGE', `sep10-auth: function must be ${WEB_AUTH_FUNCTION_NAME}`);
  }
  const callArgs = call.args();
  if (callArgs.length !== 1 || callArgs[0].switch().value !== xdr.ScValType.scvMap().value) {
    throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: expected a single map argument');
  }

  const args: Record<string, string> = {};
  for (const item of callArgs[0].map() ?? []) {
    if (
      item.key().switch().value !== xdr.ScValType.scvString().value ||
      item.val().switch().value !== xdr.ScValType.scvString().value
    ) {
      throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: argument map must be Map<String,String>');
    }
    args[item.key().str().toString()] = item.val().str().toString();
  }
  return { args, raw: callArgs[0].toXDR('base64') };
}

/** Returns the `{public_key, signature}` bytes of an ed25519 address signature. */
function readSignature(creds: xdr.SorobanAddressCredentials): { publicKey: Buffer; signature: Buffer } | null {
  const sig = creds.signature();
  if (sig.switch().value !== xdr.ScValType.scvVec().value) return null;
  const vec = sig.vec() ?? [];
  if (vec.length !== 1 || vec[0].switch().value !== xdr.ScValType.scvMap().value) return null;

  let publicKey: Buffer | undefined;
  let signature: Buffer | undefined;
  for (const item of vec[0].map() ?? []) {
    if (item.key().switch().value !== xdr.ScValType.scvSymbol().value) continue;
    const name = item.key().sym().toString();
    if (item.val().switch().value !== xdr.ScValType.scvBytes().value) continue;
    if (name === 'public_key') publicKey = Buffer.from(item.val().bytes());
    if (name === 'signature') signature = Buffer.from(item.val().bytes());
  }
  return publicKey && signature ? { publicKey, signature } : null;
}

function hasSignature(creds: xdr.SorobanAddressCredentials): boolean {
  const sig = creds.signature();
  if (sig.switch().value === xdr.ScValType.scvVoid().value) return false;
  if (sig.switch().value === xdr.ScValType.scvVec().value) return (sig.vec() ?? []).length > 0;
  return true;
}

/**
 * Verifies a client-returned SEP-45 challenge. Like `verifyChallenge` it never
 * throws; failures are returned with a {@link VerifyErrorCode}.
 *
 * Checks, in order: option validity, entry structure (one server entry, one
 * contract-account client entry, both calling `web_auth_verify` on
 * `webAuthContractId` with identical arguments), argument values (`account`,
 * `home_domain`, `web_auth_domain`, `web_auth_domain_account`), expiry, the
 * server's ed25519 signature, and finally the client's authorization via
 * `options.verifyClientAuthorization`.
 */
export async function verifyContractChallenge(
  authorizationEntries: string[],
  options: VerifyContractChallengeOptions,
): Promise<VerifyContractChallengeResult> {
  const fail = (code: VerifyErrorCode, message: string): VerifyContractChallengeResult => ({
    valid: false,
    address: '',
    error: `sep10-auth: ${message}`,
    errorCode: code,
  });

  if (!StrKey.isValidEd25519PublicKey(options.serverAccountId)) {
    return fail('INVALID_SERVER_ACCOUNT_ID', `Invalid serverAccountId: ${options.serverAccountId}`);
  }
  if (!StrKey.isValidContract(options.webAuthContractId)) {
    return fail('INVALID_OPTIONS', `Invalid webAuthContractId: ${options.webAuthContractId}`);
  }

  const homeDomains = Array.isArray(options.homeDomains) ? options.homeDomains : [options.homeDomains];
  const webAuthDomains = Array.isArray(options.webAuthDomain)
    ? options.webAuthDomain
    : [options.webAuthDomain];
  try {
    homeDomains.forEach((d) => assertBareDomain('homeDomains', d));
    webAuthDomains.forEach((d) => assertBareDomain('webAuthDomain', d));
  } catch (error) {
    return fail('INVALID_OPTIONS', (error as Error).message.replace(/^sep10-auth: /, ''));
  }

  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET;

  try {
    if (authorizationEntries.length !== 2) {
      throw new ContractChallengeError(
        'INVALID_CHALLENGE',
        'sep10-auth: expected exactly two authorization entries (server and client)',
      );
    }
    const entries = authorizationEntries.map((b64) =>
      xdr.SorobanAuthorizationEntry.fromXDR(b64, 'base64'),
    );

    const parsed = entries.map((entry) => ({
      entry,
      address: entryAddress(entry),
      ...readArgs(entry, options.webAuthContractId),
    }));
    if (parsed[0].raw !== parsed[1].raw) {
      throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: entries carry different arguments');
    }

    const server = parsed.find((p) => p.address === options.serverAccountId);
    const client = parsed.find((p) => p !== server);
    if (!server || !client) {
      throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: server authorization entry missing');
    }
    if (!StrKey.isValidContract(client.address)) {
      throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: client entry must be a contract account');
    }

    const { args } = server;
    if (args.account !== client.address) {
      throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: account argument does not match client entry');
    }
    if (args.web_auth_domain_account !== options.serverAccountId) {
      throw new ContractChallengeError('WRONG_SIGNER', 'sep10-auth: web_auth_domain_account is not the server account');
    }
    if (!homeDomains.includes(args.home_domain)) {
      throw new ContractChallengeError('WRONG_DOMAIN', `sep10-auth: unexpected home_domain "${args.home_domain}"`);
    }
    if (!webAuthDomains.includes(args.web_auth_domain)) {
      throw new ContractChallengeError('WRONG_DOMAIN', `sep10-auth: unexpected web_auth_domain "${args.web_auth_domain}"`);
    }
    if (!args.nonce) {
      throw new ContractChallengeError('INVALID_CHALLENGE', 'sep10-auth: nonce argument missing');
    }

    const serverCreds = addressCredentials(server.entry);
    const clientCreds = addressCredentials(client.entry);
    if (options.currentLedger !== undefined) {
      if (
        serverCreds.signatureExpirationLedger() < options.currentLedger ||
        clientCreds.signatureExpirationLedger() < options.currentLedger
      ) {
        throw new ContractChallengeError('CHALLENGE_EXPIRED', 'sep10-auth: challenge expired');
      }
    }

    // The server entry must carry the server's own valid ed25519 signature.
    const serverSig = readSignature(serverCreds);
    const preimage = buildAuthorizationEntryPreimage(
      server.entry,
      serverCreds.signatureExpirationLedger(),
      networkPassphrase,
    );
    if (
      !serverSig ||
      !serverSig.publicKey.equals(StrKey.decodeEd25519PublicKey(options.serverAccountId)) ||
      !Keypair.fromPublicKey(options.serverAccountId).verify(hash(preimage.toXDR()), serverSig.signature)
    ) {
      throw new ContractChallengeError('WRONG_SIGNER', 'sep10-auth: invalid server signature');
    }

    if (!hasSignature(clientCreds) || !(await options.verifyClientAuthorization(client.entry, entries))) {
      throw new ContractChallengeError('WRONG_SIGNER', 'sep10-auth: client authorization not valid');
    }

    return { valid: true, address: client.address, nonce: args.nonce, homeDomain: args.home_domain };
  } catch (error) {
    if (error instanceof ContractChallengeError) return fail(error.code, error.message.replace(/^sep10-auth: /, ''));
    return fail('INVALID_CHALLENGE', error instanceof Error ? error.message : String(error));
  }
}
