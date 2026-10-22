/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

/**
 * main.ts — Entry point for the SEP-10 browser login demo.
 *
 * Orchestrates the two-phase UI:
 *
 *   Phase A (pre-login)
 *     "Connect Freighter" → obtains the public key and transitions to phase B.
 *
 *   Phase B (authenticated)
 *     "Login with SEP-10" → runs the full challenge/sign/submit flow.
 *     "Logout" → clears the session and returns to phase A.
 *
 * This file deliberately contains no business logic — that all lives in
 * sep10.ts. main.ts only wires DOM events to the helpers in ui.ts and sep10.ts.
 */

import {
  connectFreighter,
  runSep10Login,
  getStoredToken,
  clearSession,
  isFreighterAvailable,
} from './sep10';

import {
  setStatus,
  activateStep,
  markAllStepsDone,
  resetSteps,
  showConnectButton,
  showLoginButton,
  showLogoutButton,
  setButtonsDisabled,
  showResultPanel,
  hideResultPanel,
  log,
} from './ui';

// ── State ─────────────────────────────────────────────────────────────────
// Minimal state object — avoid global variables scattered around.
const state = {
  address: '',
};

// ── Initialisation ─────────────────────────────────────────────────────────

async function init(): Promise<void> {
  log('App initialised.');

  // Check Freighter availability upfront so we can hint the user immediately.
  const available = await isFreighterAvailable();
  if (!available) {
    log('Freighter extension not detected.');
    setStatus(
      '⚠️ Freighter is not installed. ' +
        '<a href="https://www.freighter.app/" target="_blank" rel="noopener">Install it</a> ' +
        'and reload the page.',
      'error',
    );
    setButtonsDisabled(true);
    return;
  }
  log('Freighter extension detected.');

  // If there is already a stored token (e.g. after a same-tab refresh) try to
  // restore the connected address and skip straight to the authenticated state.
  const existingToken = getStoredToken();
  if (existingToken) {
    log('Existing session token found — attempting to restore session.');
    try {
      const address = await connectFreighter();
      state.address = address;
      restoreSession(address, existingToken);
      return;
    } catch {
      log('Could not restore session — clearing stored token.');
      clearSession();
    }
  }

  setStatus('Click <strong>Connect Freighter</strong> to begin.', 'idle');
  showConnectButton();
}

// ── Session restore ────────────────────────────────────────────────────────

function restoreSession(address: string, token: string): void {
  log(`Session restored for ${address}.`);
  markAllStepsDone();
  showResultPanel(
    address,
    token,
    import.meta.env.VITE_NETWORK_PASSPHRASE ?? 'Test SDF Network ; September 2015',
  );
  showLogoutButton();
  setStatus(`Logged in as <strong>${address}</strong>`, 'success');
}

// ── Button: Connect Freighter ─────────────────────────────────────────────

async function handleConnect(): Promise<void> {
  log('Connect button clicked.');
  setButtonsDisabled(true);
  activateStep('connect');
  setStatus('Connecting to Freighter…', 'loading');

  try {
    const address = await connectFreighter();
    state.address = address;
    log(`Connected: ${address}`);
    setStatus(`Connected as <strong>${address}</strong>. Click Login to authenticate.`, 'success');
    showLoginButton(address);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log(`Connect failed: ${message}`);
    setStatus(`❌ ${message}`, 'error');
    resetSteps();
    showConnectButton();
  } finally {
    setButtonsDisabled(false);
  }
}

// ── Button: Login with SEP-10 ─────────────────────────────────────────────

async function handleLogin(): Promise<void> {
  if (!state.address) {
    log('Login clicked but no address — aborting.');
    return;
  }
  log('Login button clicked. Starting SEP-10 flow…');
  setButtonsDisabled(true);
  setStatus('Starting SEP-10 flow…', 'loading');

  try {
    const session = await runSep10Login((step) => {
      activateStep(step);
      const labels: Record<string, string> = {
        connect: 'Connecting to Freighter…',
        challenge: 'Fetching challenge from server…',
        sign: 'Waiting for Freighter to sign the challenge…',
        submit: 'Submitting signed challenge to server…',
      };
      const label = labels[step] ?? `Step: ${step}`;
      log(label);
      setStatus(label, 'loading');
    });

    log(`Login successful. JWT received (${session.token.length} chars).`);
    markAllStepsDone();
    showResultPanel(session.address, session.token, session.networkPassphrase);
    showLogoutButton();
    setStatus(`✅ Authenticated as <strong>${session.address}</strong>`, 'success');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log(`Login failed: ${message}`);
    setStatus(`❌ ${message}`, 'error');
    // Restore the login button so the user can try again.
    showLoginButton(state.address);
  } finally {
    setButtonsDisabled(false);
  }
}

// ── Button: Logout ────────────────────────────────────────────────────────

function handleLogout(): void {
  log('Logout clicked.');
  clearSession();
  state.address = '';
  hideResultPanel();
  resetSteps();
  showConnectButton();
  setStatus('Logged out. Click <strong>Connect Freighter</strong> to begin again.', 'idle');
}

// ── Wire up event listeners ────────────────────────────────────────────────

document.getElementById('btn-connect')!.addEventListener('click', () => void handleConnect());
document.getElementById('btn-login')!.addEventListener('click', () => void handleLogin());
document.getElementById('btn-logout')!.addEventListener('click', handleLogout);

// ── Boot ───────────────────────────────────────────────────────────────────

void init();
