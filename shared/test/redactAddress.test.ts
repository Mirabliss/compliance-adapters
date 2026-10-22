/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { redactAddress } from '../src/index';

describe('redactAddress', () => {
  it('redacts G addresses as first4…last4', () => {
    expect(redactAddress('GABC1234WXYZ')).toBe('GABC…WXYZ');
  });

  it('redacts M and C addresses the same way', () => {
    expect(redactAddress('MABC1234WXYZ')).toBe('MABC…WXYZ');
    expect(redactAddress('CABC1234WXYZ')).toBe('CABC…WXYZ');
  });

  it('returns placeholder for invalid input', () => {
    expect(redactAddress('')).toBe('[invalid-address]');
    expect(redactAddress('short')).toBe('[invalid-address]');
    expect(redactAddress(undefined)).toBe('[invalid-address]');
    expect(redactAddress(123)).toBe('[invalid-address]');
  });
});
