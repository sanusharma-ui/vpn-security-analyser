/**
 * Security Policy & Baseline Standards View
 * Details cryptographic requirements, severity weights, and protocol scope.
 */
import { api } from '../api.js';
import { icon } from '../components/icons.js';
import { escapeHtml } from '../components/ui.js';

export class PolicyView {
  constructor(app) {
    this.app = app;
    this.container = document.getElementById('view-policy');
  }

  async render() {
    this.container.innerHTML = `
      <div class="policy-view-container max-w-5xl mx-auto">
        <!-- HEADER -->
        <div class="view-header text-center mb-8">
          <h2 class="text-2xl font-bold mb-2">Cryptographic Policy & Security Baseline</h2>
          <p class="text-muted max-w-xl mx-auto">
            Deterministic rule evaluation based on the local security baseline. Not a third-party security certification.
          </p>
        </div>

        <div id="policy-content-body">
          <div class="p-8 text-center text-muted">
            <span class="spinner-large mb-3"></span>
            <p>Loading security policy parameters...</p>
          </div>
        </div>
      </div>
    `;

    try {
      const data = await api.getPolicy();
      this.renderPolicyData(data);
    } catch (err) {
      this.container.querySelector('#policy-content-body').innerHTML = `
        <div class="card glass-panel error-card p-6 text-center text-red">
          ${icon('alertTriangle', 'w-8 h-8 mx-auto mb-2')}
          <h4 class="font-bold">Failed to load policy baseline</h4>
          <p class="text-sm text-muted mb-4">${escapeHtml(err.message)}</p>
        </div>
      `;
    }
  }

  renderPolicyData(policy) {
    const body = this.container.querySelector('#policy-content-body');
    if (!body) return;

    const weights = policy.risk_weights || { low: 10, medium: 30, high: 60, critical: 100 };
    const supported = policy.supported_protocols || [];
    const unsupported = policy.unsupported || [];
    const baseline = policy.baseline || {};

    body.innerHTML = `
      <!-- RISK WEIGHTS MATRIX -->
      <div class="card glass-panel mb-6">
        <div class="card-header flex items-center gap-2 mb-4">
          ${icon('shieldAlert', 'w-5 h-5 text-amber')}
          <h3 class="card-title">Risk Severity Scoring Weights</h3>
        </div>
        <p class="text-sm text-muted mb-4">
          ${escapeHtml(policy.aggregation || 'Maximum confirmed severity; offered and suspected findings excluded.')}
        </p>

        <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div class="weight-box weight-low">
            <span class="weight-name">Low Severity</span>
            <span class="weight-value font-mono">-${weights.low || 10} pts</span>
          </div>
          <div class="weight-box weight-medium">
            <span class="weight-name">Medium Severity</span>
            <span class="weight-value font-mono">-${weights.medium || 30} pts</span>
          </div>
          <div class="weight-box weight-high">
            <span class="weight-name">High Severity</span>
            <span class="weight-value font-mono">-${weights.high || 60} pts</span>
          </div>
          <div class="weight-box weight-critical">
            <span class="weight-name">Critical Severity</span>
            <span class="weight-value font-mono">-${weights.critical || 100} pts</span>
          </div>
        </div>
      </div>

      <!-- PROTOCOL SCOPE & LIMITATIONS -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <!-- SUPPORTED -->
        <div class="card glass-panel">
          <div class="card-header flex items-center gap-2 mb-3">
            ${icon('checkCircle', 'w-5 h-5 text-emerald')}
            <h4 class="card-title text-base">Supported Protocols</h4>
          </div>
          <p class="text-xs text-muted mb-3">
            Hardware capture and passive parsing covers:
          </p>
          <ul class="scope-list">
            ${supported.map(p => `
              <li>
                ${icon('check', 'w-4 h-4 text-emerald inline mr-2')}
                <strong class="text-cyan">${escapeHtml(p)}</strong>
              </li>
            `).join('')}
          </ul>
        </div>

        <!-- EXCLUDED / UNSUPPORTED -->
        <div class="card glass-panel">
          <div class="card-header flex items-center gap-2 mb-3">
            ${icon('shield', 'w-5 h-5 text-amber')}
            <h4 class="card-title text-base">Out of Scope / Unsupported</h4>
          </div>
          <p class="text-xs text-muted mb-3">
            The analyzer deliberately excludes non-passive or untrusted checks:
          </p>
          <ul class="scope-list">
            ${unsupported.map(u => `
              <li>
                ${icon('x', 'w-4 h-4 text-red inline mr-2')}
                <span>${escapeHtml(u)}</span>
              </li>
            `).join('')}
          </ul>
        </div>
      </div>

      <!-- SCORE CONTRACT PRINCIPLES -->
      <div class="card glass-panel mb-6">
        <div class="card-header flex items-center gap-2 mb-3">
          ${icon('bookOpen', 'w-5 h-5 text-cyan')}
          <h3 class="card-title">Score Contract Principles (Zero Uncertainty Concealment)</h3>
        </div>
        <div class="text-sm text-muted space-y-2 leading-relaxed">
          <p>
            • <strong>Provisional Nature:</strong> Scores are calculated as <code>100 - risk</code> only when every retained SA has complete, unambiguous, and fully observed cryptographic transforms.
          </p>
          <p>
            • <strong>Insufficient Evidence Rule:</strong> If handshakes are unobserved, ESP-only traffic is present, or queue drops occur, the score is strictly suppressed (null) and rendered as <em>Insufficient Evidence</em>.
          </p>
          <p>
            • <strong>Replay Suspicions:</strong> Duplicate ESP sequence counters remain labeled as <code>SUSPECTED</code> rather than assumed breaches.
          </p>
        </div>
      </div>
    `;
  }
}
