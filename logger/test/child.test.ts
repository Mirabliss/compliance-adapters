/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { consoleLogger, noopLogger, createLeveledLogger, getChildLogger, Logger } from '../src/index';

function makeSpyLogger(): Logger & Record<'debug' | 'info' | 'warn' | 'error', jest.Mock> {
  return {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };
}

describe('child loggers (issue #830)', () => {
  it('bindings appear on all child log lines', () => {
    const base = makeSpyLogger();
    const leveled = createLeveledLogger(base, 'debug');
    const child = getChildLogger(leveled, { contractId: 'C1', runId: 'R1' });
    child.info('hello');
    expect(base.info).toHaveBeenCalledWith({ contractId: 'C1', runId: 'R1' }, 'hello');
    child.error('boom', 42);
    expect(base.error).toHaveBeenCalledWith({ contractId: 'C1', runId: 'R1' }, 'boom', 42);
  });

  it('nested children merge bindings with inner winning', () => {
    const base = makeSpyLogger();
    const parent = getChildLogger(base, { a: 1, shared: 'outer' });
    const nested = getChildLogger(parent, { b: 2, shared: 'inner' });
    nested.warn('msg');
    expect(base.warn).toHaveBeenCalledWith({ a: 1, b: 2, shared: 'inner' }, 'msg');
  });

  it('consoleLogger.child prepends bindings to console calls', () => {
    const spy = jest.spyOn(console, 'info').mockImplementation(() => undefined);
    try {
      const child = consoleLogger.child!({ provider: 'p1' });
      child.info('hi');
      expect(spy).toHaveBeenCalledWith({ provider: 'p1' }, 'hi');
    } finally {
      spy.mockRestore();
    }
  });

  it('noopLogger.child stays silent', () => {
    const child = noopLogger.child!({ x: 1 });
    expect(() => {
      child.debug('d');
      child.info('i');
      child.warn('w');
      child.error('e');
    }).not.toThrow();
  });

  it('falls back to wrapper when base has no child method', () => {
    const base = makeSpyLogger();
    delete (base as Partial<Logger>).child;
    const child = getChildLogger(base, { runId: 'R9' });
    child.debug('d');
    expect(base.debug).toHaveBeenCalledWith({ runId: 'R9' }, 'd');
  });
});
