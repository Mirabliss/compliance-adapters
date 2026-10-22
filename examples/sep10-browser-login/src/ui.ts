/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * ui.ts — DOM interaction helpers.
 *
 * Keeps all querySelector / classList / innerHTML manipulation in one place
 * so main.ts stays readable.
 */

// ── Step IDs ──────────────────────────────────────────────────────────────
type StepId = 'connect' | 'challenge' | 'sign' | 'token';

const STEP_ELEMENT_IDS: Record<StepId, string> = {
  connect: 'step-connect',
  challenge: 'step-challenge',
  sign: 'step-sign',
  token: 'step-token',
};

// Map from the progress event names emitted by runSep10Login to the
// corresponding step element.
const PROGRESS_TO_STEP: Record<string, StepId> = {
  connect: 'connect',
  challenge: 'challenge',
  sign: 'sign',
  submit: 'token',
};

// ── Helpers ───────────────────────────────────────────────────────────────

function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Element #${id} not found`);
  return el;
}

// ── Exported UI functions ─────────────────────────────────────────────────

export function setStatus(
  message: string,
  variant: 'idle' | 'loading' | 'success' | 'error' = 'idle',
): void {
  const el = $('status');
  el.innerHTML = message;
  el.className = `status status--${variant}`;
}

export function activateStep(progressEvent: string): void {
  const stepId = PROGRESS_TO_STEP[progressEvent];
  if (!stepId) return;

  // Mark all prior steps as done.
  const order: StepId[] = ['connect', 'challenge', 'sign', 'token'];
  const currentIndex = order.indexOf(stepId);

  order.forEach((id, index) => {
    const el = document.getElementById(STEP_ELEMENT_IDS[id]);
    if (!el) return;
    el.classList.remove('step--active', 'step--done');
    if (index < currentIndex) {
      el.classList.add('step--done');
    } else if (index === currentIndex) {
      el.classList.add('step--active');
    }
  });
}

export function markAllStepsDone(): void {
  const order: StepId[] = ['connect', 'challenge', 'sign', 'token'];
  order.forEach((id) => {
    const el = document.getElementById(STEP_ELEMENT_IDS[id]);
    if (el) {
      el.classList.remove('step--active');
      el.classList.add('step--done');
    }
  });
}

export function resetSteps(): void {
  const order: StepId[] = ['connect', 'challenge', 'sign', 'token'];
  order.forEach((id) => {
    const el = document.getElementById(STEP_ELEMENT_IDS[id]);
    if (el) el.classList.remove('step--active', 'step--done');
  });
}

export function showConnectButton(): void {
  $('btn-connect').removeAttribute('hidden');
  $('btn-login').setAttribute('hidden', '');
  $('btn-logout').setAttribute('hidden', '');
}

export function showLoginButton(address: string): void {
  $('btn-connect').setAttribute('hidden', '');
  const loginBtn = $('btn-login');
  loginBtn.removeAttribute('hidden');
  loginBtn.textContent = `Login as ${address.slice(0, 6)}…${address.slice(-4)}`;
  $('btn-logout').setAttribute('hidden', '');
}

export function showLogoutButton(): void {
  $('btn-connect').setAttribute('hidden', '');
  $('btn-login').setAttribute('hidden', '');
  $('btn-logout').removeAttribute('hidden');
}

export function setButtonsDisabled(disabled: boolean): void {
  (['btn-connect', 'btn-login', 'btn-logout'] as const).forEach((id) => {
    const btn = document.getElementById(id) as HTMLButtonElement | null;
    if (btn) btn.disabled = disabled;
  });
}

export function showResultPanel(address: string, token: string, network: string): void {
  const panel = $('result-panel');
  panel.removeAttribute('hidden');
  $('result-address').textContent = address;
  $('result-network').textContent = network;
  $('result-token').textContent = token;
}

export function hideResultPanel(): void {
  $('result-panel').setAttribute('hidden', '');
}

// ── Debug log ─────────────────────────────────────────────────────────────

export function log(message: string): void {
  const el = $('log');
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 23);
  el.textContent += `[${ts}] ${message}\n`;
  // Auto-scroll to bottom.
  el.scrollTop = el.scrollHeight;
  // Also write to the browser console for developer convenience.
  console.log(`[sep10-demo] ${message}`);
}
