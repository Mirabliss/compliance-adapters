/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { Keypair } from '@stellar/stellar-sdk';

/**
 * Pluggable transaction signer so the oracle key can live in a KMS/HSM
 * instead of process memory. `sign` receives the 32-byte transaction hash and
 * must return a raw 64-byte Ed25519 signature.
 */
export interface Signer {
  publicKey(): string;
  sign(txHash: Buffer): Promise<Buffer>;
}

/** Default {@link Signer} backed by an in-memory `Keypair`. */
export class KeypairSigner implements Signer {
  constructor(private readonly keypair: Keypair) {}

  publicKey(): string {
    return this.keypair.publicKey();
  }

  async sign(txHash: Buffer): Promise<Buffer> {
    return this.keypair.sign(txHash);
  }
}

/** Accepts either a `Keypair` (backward compatible) or any {@link Signer}. */
export function toSigner(signer: Keypair | Signer): Signer {
  return signer instanceof Keypair ? new KeypairSigner(signer) : signer;
}

/** Signs `tx` with `signer` by adding a decorated signature over its hash. */
export async function signTransaction(
  tx: { hash(): Buffer; addSignature(publicKey: string, signature: string): void },
  signer: Signer,
): Promise<void> {
  const signature = await signer.sign(tx.hash());
  tx.addSignature(signer.publicKey(), signature.toString('base64'));
}
