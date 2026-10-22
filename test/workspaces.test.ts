/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import * as fs from 'fs';
import * as path from 'path';

describe('root workspaces (issue #835)', () => {
  it('contains no duplicate entries', () => {
    const pkgPath = path.resolve(__dirname, '..', 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    const workspaces: string[] = pkg.workspaces;
    expect(new Set(workspaces).size).toBe(workspaces.length);
  });

  it('is ordered topologically (foundations before dependents)', () => {
    const pkgPath = path.resolve(__dirname, '..', 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    const workspaces: string[] = pkg.workspaces;
    const order = [
      'backoff',
      'logger',
      'shared',
      'tracing-types',
      'metrics',
      'tracing',
      'sep10-auth',
      'sanctions-oracle',
      'horizon-listener',
      'examples/full-stack-demo',
      'examples/sep10-sanctions-gate',
      'e2e-tests',
    ];
    expect(workspaces).toEqual(order);
  });
});
