import { DefaultTracer, extractTraceContext } from '../src/index';

describe('W3C traceparent propagation (#825)', () => {
  it('header follows W3C format and round-trips', () => {
    const tracer = new DefaultTracer();
    const span = tracer.startSpan('op');
    const header = tracer.injectContext({ traceId: span.traceId, spanId: span.spanId });
    expect(header).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]$/);
    const ctx = extractTraceContext({ traceparent: header });
    expect(ctx).toEqual({ traceId: span.traceId, spanId: span.spanId, sampled: true });
    const child = tracer.startSpan('child', ctx);
    expect(child.traceId).toBe(span.traceId);
  });

  it('can be disabled (no header extracted)', () => {
    expect(extractTraceContext({})).toBeUndefined();
    expect(extractTraceContext({ traceparent: 'bogus' })).toBeUndefined();
  });
});
