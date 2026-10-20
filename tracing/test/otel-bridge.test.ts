/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { createOtelTracer, OtelSpanLike, OtelTracerLike } from '../src/index';

/** In-memory fake OTel tracer/span for tests (no @opentelemetry/api needed). */
class FakeOtelSpan implements OtelSpanLike {
  attributes: Record<string, string | number | boolean> = {};
  status: { code: number; message?: string } | undefined;
  exceptions: Error[] = [];
  ended = false;

  constructor(
    readonly name: string,
    private readonly ctx: { traceId: string; spanId: string },
  ) {}

  setAttribute(key: string, value: string | number | boolean): void {
    this.attributes[key] = value;
  }

  setStatus(status: { code: number; message?: string }): void {
    this.status = status;
  }

  recordException(error: Error): void {
    this.exceptions.push(error);
  }

  end(): void {
    this.ended = true;
  }

  spanContext(): { traceId: string; spanId: string } {
    return this.ctx;
  }
}

class FakeOtelTracer implements OtelTracerLike {
  readonly spans: FakeOtelSpan[] = [];

  startSpan(name: string): OtelSpanLike {
    const span = new FakeOtelSpan(name, {
      traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
      spanId: '00f067aa0ba902b7',
    });
    this.spans.push(span);
    return span;
  }
}

describe('createOtelTracer (issue #826)', () => {
  it('spans appear in the OTel tracer', () => {
    const fake = new FakeOtelTracer();
    const tracer = createOtelTracer(fake);
    const span = tracer.startSpan('address_check');
    span.end('ok');
    expect(fake.spans).toHaveLength(1);
    expect(fake.spans[0].name).toBe('address_check');
    expect(fake.spans[0].ended).toBe(true);
    expect(span.traceId).toBe('4bf92f3577b34da6a3ce929d0e0e4736');
    expect(span.spanId).toBe('00f067aa0ba902b7');
  });

  it('attributes and status map correctly', () => {
    const fake = new FakeOtelTracer();
    const tracer = createOtelTracer(fake);
    const ok = tracer.startSpan('a');
    ok.setAttribute('phase', 'address_check');
    ok.setAttribute('retries', 2);
    ok.end('ok');
    expect(fake.spans[0].attributes).toEqual({ phase: 'address_check', retries: 2 });
    expect(fake.spans[0].status).toEqual({ code: 1 });

    const err = tracer.startSpan('b');
    err.end('error', new Error('denied'));
    expect(fake.spans[1].status).toEqual({ code: 2, message: 'denied' });
    expect(fake.spans[1].exceptions).toHaveLength(1);
  });

  it('supports context inject/extract round-trip', () => {
    const tracer = createOtelTracer(new FakeOtelTracer());
    const header = tracer.injectContext({
      traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
      spanId: '00f067aa0ba902b7',
    });
    expect(tracer.extractContext(header)).toEqual({
      traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
      spanId: '00f067aa0ba902b7',
    });
  });
});
