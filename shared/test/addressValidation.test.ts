/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * Tests for isValidStellarAddress utility.
 * Issue #125: Add a shared TypeScript utility type/package for cross-package
 * Stellar address validation.
 */

import { Keypair } from '@stellar/stellar-sdk';
import { isValidStellarAddress, normalizeStellarAddress } from '../src/index';

describe('isValidStellarAddress', () => {
  it('returns true for a valid Ed25519 public key (G... prefix)', () => {
    const validAddress = Keypair.random().publicKey();
    expect(isValidStellarAddress(validAddress)).toBe(true);
  });

  it('returns false for an empty string', () => {
    expect(isValidStellarAddress('')).toBe(false);
  });

  it('returns false for a string with an invalid prefix', () => {
    expect(isValidStellarAddress('MAAZI4T7S6XNVW5RQFYNLJNHVBRFXRWUN5Q3NXPKV2HCEHZ3Y7WV2QHJR')).toBe(false);
  });

  it('returns false for a string that is too short', () => {
    expect(isValidStellarAddress('GABC')).toBe(false);
  });

  it('returns false for a string with lowercase letters in the payload', () => {
    expect(isValidStellarAddress('GaaZI4T7S6XNVW5RQFYNLJNHVBRFXRWUN5Q3NXPKV2HCEHZ3Y7WV2QHJR')).toBe(false);
  });

  it('returns false for a random non-Stellar string', () => {
    expect(isValidStellarAddress('not-a-stellar-address')).toBe(false);
  });
});

describe('normalizeStellarAddress', () => {
  const address = Keypair.random().publicKey();

  it('trims surrounding whitespace', () => {
    expect(normalizeStellarAddress(`  ${address}\t\n`)).toBe(address);
  });

  it('uppercases a lowercase address', () => {
    expect(normalizeStellarAddress(address.toLowerCase())).toBe(address);
  });

  it('maps mixed-case and padded input to one canonical, valid address', () => {
    const messy = ` ${address.slice(0, 20).toLowerCase()}${address.slice(20)} `;
    expect(normalizeStellarAddress(messy)).toBe(address);
    expect(isValidStellarAddress(normalizeStellarAddress(messy))).toBe(true);
  });

  it('does not validate: garbage stays invalid after normalizing', () => {
    expect(isValidStellarAddress(normalizeStellarAddress(' not-a-stellar-address '))).toBe(false);
  });
});
