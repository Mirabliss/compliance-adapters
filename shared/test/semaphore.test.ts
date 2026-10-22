/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * Tests for createSemaphore utility.
 * Issue #299: Extract shared semaphore/concurrency-limiting primitive.
 */

import { createSemaphore, SemaphoreTimeoutError } from '../src/semaphore';

describe('createSemaphore', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('allows up to N concurrent acquisitions', async () => {
    const semaphore = createSemaphore(2);
    const activeCount: number[] = [];
    let currentActive = 0;

    const task = async () => {
      const release = await semaphore.acquire();
      currentActive++;
      activeCount.push(currentActive);
      const maxObserved = currentActive;

      await new Promise((resolve) => setTimeout(resolve, 100));

      currentActive--;
      release();
      return maxObserved;
    };

    const maxConcurrentPromise = Promise.all([task(), task(), task(), task()]);
    await jest.advanceTimersByTimeAsync(250);
    const maxConcurrent = await maxConcurrentPromise;

    // All tasks should observe <= 2 concurrent
    expect(Math.max(...maxConcurrent)).toBeLessThanOrEqual(2);
  });

  it('queues acquisitions beyond the limit and processes in FIFO order', async () => {
    const semaphore = createSemaphore(1);
    const order: string[] = [];

    const task = async (name: string) => {
      const release = await semaphore.acquire();
      try {
        order.push(`${name}-start`);
        await new Promise((resolve) => setTimeout(resolve, 10));
        order.push(`${name}-end`);
      } finally {
        release();
      }
    };

    // Start three tasks; only the first runs immediately
    const p1 = task('A');
    const p2 = task('B');
    const p3 = task('C');

    // Advance time to complete the sequence
    await jest.advanceTimersByTimeAsync(50);
    await Promise.all([p1, p2, p3]);

    // Verify FIFO ordering: A completes before B can start
    expect(order).toEqual([
      'A-start',
      'A-end',
      'B-start',
      'B-end',
      'C-start',
      'C-end',
    ]);
  });

  it('supports releasing and reacquiring the same semaphore', async () => {
    const semaphore = createSemaphore(1);
    let timesAcquired = 0;

    const release1 = await semaphore.acquire();
    timesAcquired++;
    expect(timesAcquired).toBe(1);

    release1();

    const release2 = await semaphore.acquire();
    timesAcquired++;
    expect(timesAcquired).toBe(2);

    release2();
  });

  it('does not allow double release to exceed configured concurrency', async () => {
    const semaphore = createSemaphore(1);
    const release1 = await semaphore.acquire();

    release1();
    release1();

    const order: string[] = [];
    const task = async (name: string) => {
      const release = await semaphore.acquire();
      try {
        order.push(`${name}-start`);
        await new Promise((resolve) => setTimeout(resolve, 10));
        order.push(`${name}-end`);
      } finally {
        release();
      }
    };

    const p1 = task('A');
    const p2 = task('B');

    await jest.advanceTimersByTimeAsync(30);
    await Promise.all([p1, p2]);

    expect(order).toEqual(['A-start', 'A-end', 'B-start', 'B-end']);
  });

  it('throws or rejects if limit is 0 or negative', () => {
    expect(() => createSemaphore(0)).toThrow();
    expect(() => createSemaphore(-1)).toThrow();
  });

  it('allows unlimited concurrency when initialized with Infinity', async () => {
    const semaphore = createSemaphore(Infinity);
    const releases: Array<() => void> = [];

    // Acquire many times without waiting
    for (let i = 0; i < 1000; i++) {
      const release = await Promise.resolve().then(() => semaphore.acquire());
      releases.push(release);
    }

    // All acquisitions should resolve immediately with no queue
    expect(releases).toHaveLength(1000);

    // Clean up
    releases.forEach((r) => r());
  });

  it('handles concurrent releases and acquisitions without deadlock', async () => {
    const semaphore = createSemaphore(3);
    const completedTasks: string[] = [];

    const worker = async (id: number, duration: number) => {
      const release = await semaphore.acquire();
      try {
        await new Promise((resolve) => setTimeout(resolve, duration));
        completedTasks.push(`task-${id}`);
      } finally {
        release();
      }
    };

    // Start workers with varying durations
    const promises = [
      worker(1, 50),
      worker(2, 30),
      worker(3, 40),
      worker(4, 20),
      worker(5, 60),
    ];

    await jest.advanceTimersByTimeAsync(200);
    await Promise.all(promises);

    expect(completedTasks).toHaveLength(5);
  });

  it('rejects with SemaphoreTimeoutError and removes the waiter on timeout', async () => {
    const semaphore = createSemaphore(1);
    const release = await semaphore.acquire();

    const timedOut = semaphore.acquire({ timeoutMs: 50 });
    const assertion = expect(timedOut).rejects.toBeInstanceOf(
      SemaphoreTimeoutError,
    );
    await jest.advanceTimersByTimeAsync(60);
    await assertion;

    // The timed-out waiter must be gone: a later acquire is granted first.
    release();
    const release2 = await semaphore.acquire();
    release2();
  });

  it('leaves other waiters unaffected when one waiter times out', async () => {
    const semaphore = createSemaphore(1);
    const order: string[] = [];
    const release = await semaphore.acquire();

    const doomed = semaphore.acquire({ timeoutMs: 10 });
    const doomedAssertion = expect(doomed).rejects.toBeInstanceOf(
      SemaphoreTimeoutError,
    );

    const survivor = (async () => {
      const r = await semaphore.acquire();
      order.push('survivor-acquired');
      r();
    })();

    await jest.advanceTimersByTimeAsync(20);
    await doomedAssertion;

    release();
    await survivor;
    expect(order).toEqual(['survivor-acquired']);
  });

  it('rejects immediately when the abort signal is already aborted', async () => {
    const semaphore = createSemaphore(1);
    await expect(
      semaphore.acquire({ signal: AbortSignal.abort() }),
    ).rejects.toBeDefined();
  });
});
