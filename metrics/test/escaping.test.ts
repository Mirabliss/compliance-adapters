/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import { MetricsRegistry, escapeLabelValue, escapeHelp } from '../src/index';

describe('prometheus escaping (issue #833)', () => {
  it('escapes quotes, backslashes and newlines in label values', () => {
    expect(escapeLabelValue('a"b')).toBe('a\\"b');
    expect(escapeLabelValue('a\\b')).toBe('a\\\\b');
    expect(escapeLabelValue('a\nb')).toBe('a\\nb');
    expect(escapeLabelValue('err "x"\npath\\y')).toBe('err \\"x\\"\\npath\\\\y');
  });

  it('escapes backslashes and newlines in HELP text', () => {
    expect(escapeHelp('a\\b')).toBe('a\\\\b');
    expect(escapeHelp('a\nb')).toBe('a\\nb');
  });

  it('expose() output round-trips label values through a text-parser-style unescape', () => {
    type Phase = 'we"ird\nphase\\x';
    const phases: Phase[] = ['we"ird\nphase\\x'];
    const reg = new MetricsRegistry<Phase>({ phases, prefix: 'esc_svc' });
    reg.counter.inc('we"ird\nphase\\x', 'success');
    const out = reg.expose();
    // The raw phase must not appear unescaped inside label values.
    expect(out).toContain('phase="we\\"ird\\nphase\\\\x"');
    // A Prometheus text parser unescape recovers the original value.
    const m = out.match(/phase="((?:[^"\\]|\\.)*)"/);
    expect(m).toBeTruthy();
    const unescape = (s: string) =>
      s.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    expect(unescape(m![1])).toBe('we"ird\nphase\\x');
  });
});
