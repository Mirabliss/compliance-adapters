import { DefaultTracer } from '../src/index';

describe('configurable sampling (#827)', () => {
  it('respects sampleRate statistically', () => {
    const tracer = new DefaultTracer({ sampleRate: 0.5 });
    let live = 0;
    const N = 1000;
    for (let i = 0; i < N; i++) {
      const s = tracer.startSpan('op');
      if (s.traceId !== '') live++;
    }
    expect(live).toBeGreaterThan(300);
    expect(live).toBeLessThan(700);
  });

  it('sampleRate 0/1 boundaries', () => {
    expect(new DefaultTracer({ sampleRate: 0 }).startSpan('a').traceId).toBe('');
    expect(new DefaultTracer({ sampleRate: 1 }).startSpan('a').traceId).not.toBe('');
  });

  it('child spans inherit parent decision', () => {
    const tracer = new DefaultTracer({ sampleRate: 1 });
    const unsampledParent = { traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), sampled: false };
    expect(tracer.startSpan('child', unsampledParent).traceId).toBe('');
    const sampledParent = { traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), sampled: true };
    const child = tracer.startSpan('child', sampledParent);
    expect(child.traceId).toBe(sampledParent.traceId);
  });
});
