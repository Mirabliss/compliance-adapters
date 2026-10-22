/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { sleep } from '../src/index';

describe('sleep', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('resolves after the delay', async () => {
    const p = sleep(1000);
    jest.advanceTimersByTime(1000);
    await expect(p).resolves.toBeUndefined();
  });

  it('rejects with AbortError and clears the timer on abort', async () => {
    const controller = new AbortController();
    const p = sleep(10000, { signal: controller.signal });
    const assertion = expect(p).rejects.toMatchObject({ name: 'AbortError' });
    controller.abort();
    await assertion;
    expect(jest.getTimerCount()).toBe(0);
  });

  it('rejects immediately when already aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(sleep(1000, { signal: controller.signal })).rejects.toMatchObject({
      name: 'AbortError',
    });
  });
});
