/**
 * Gemini AI Security Intelligence Hub View
 * Generates and displays executive AI explanations based on sanitized findings.
 */
import { api } from '../api.js';
import { icon } from '../components/icons.js';
import { escapeHtml, copyToClipboard, showToast } from '../components/ui.js';

export class AiView {
  constructor(app) {
    this.app = app;
    this.container = document.getElementById('view-ai');
    this.activeJobId = null;
    this.activeJob = null;
    this.aiExplanation = null;
    this.sanitizedInput = null;
    this.loading = false;
  }

  async render(params = {}) {
    const passedId = typeof params === 'string' ? params : (params && typeof params === 'object' ? params.jobId : null);
    if (passedId) this.activeJobId = passedId;

    if (!this.activeJobId) {
      // Find latest completed job
      try {
        const jobs = await api.listJobs(10, 0);
        const finished = jobs.items.find(j => ['completed', 'stopped', 'failed'].includes(j.state));
        if (finished) this.activeJobId = finished.id;
        else if (jobs.items.length > 0) this.activeJobId = jobs.items[0].id;
      } catch {}
    }

    if (!this.activeJobId) {
      this.container.innerHTML = `
        <div class="card glass-panel text-center p-12 max-w-2xl mx-auto">
          <div class="mb-4">${icon('sparkles', 'w-16 h-16 text-violet mx-auto')}</div>
          <h2 class="text-2xl font-bold mb-2">Gemini AI Security Explainer</h2>
          <p class="text-muted mb-6">
            No completed analysis jobs available. Run a live capture or upload a PCAP file to generate AI-assisted cryptographic explanations.
          </p>
          <button class="btn btn-primary" id="btn-ai-goto-capture">
            ${icon('play', 'w-4 h-4')} Start a Capture
          </button>
        </div>
      `;
      this.container.querySelector('#btn-ai-goto-capture')?.addEventListener('click', () => {
        this.app.navigate('capture');
      });
      return;
    }

    this.container.innerHTML = `
      <div class="ai-view-container max-w-5xl mx-auto">
        <!-- HEADER -->
        <div class="view-header flex flex-wrap justify-between items-center gap-4 mb-6">
          <div>
            <div class="flex items-center gap-2 mb-1">
              <h2 class="text-2xl font-bold">Gemini AI Security Intelligence</h2>
              <span class="badge badge-ai">${icon('sparkles', 'w-3 h-3 inline')} Gemini AI</span>
            </div>
            <p class="text-muted text-sm">
              Non-authoritative contextual explanations preserving engine uncertainty. Raw credentials and payloads are strictly excluded.
            </p>
          </div>

          <div class="flex items-center gap-3">
            <button class="btn btn-secondary btn-sm" id="btn-switch-ai-job">
              ${icon('list', 'w-4 h-4')} Change Job
            </button>
            <button class="btn btn-gradient btn-sm" id="btn-trigger-explain" ${this.loading ? 'disabled' : ''}>
              ${icon('sparkles', 'w-4 h-4')} ${this.loading ? 'Analyzing...' : 'Generate AI Analysis'}
            </button>
          </div>
        </div>

        <!-- JOB CONTEXT BAR -->
        <div class="card glass-panel mb-6 p-4 flex flex-wrap justify-between items-center gap-4">
          <div class="flex items-center gap-3">
            <span class="text-xs text-muted font-mono uppercase">Assessing Job:</span>
            <code class="code-badge font-mono">${this.activeJobId}</code>
          </div>
          <div class="flex items-center gap-3 text-sm">
            <span id="ai-job-status-badge">Checking job state...</span>
          </div>
        </div>

        <!-- AI CONTENT DISPLAY -->
        <div id="ai-content-area">
          <div class="p-8 text-center text-muted">
            <span class="spinner-large mb-3"></span>
            <p>Fetching AI explanation and sanitized inputs...</p>
          </div>
        </div>

        <!-- SANITIZED AI INPUT INSPECTOR -->
        <div class="card glass-panel mt-6" id="sanitized-input-card">
          <div class="card-header flex justify-between items-center cursor-pointer" id="toggle-sanitized-input">
            <div class="flex items-center gap-2">
              ${icon('shieldCheck', 'w-5 h-5 text-cyan')}
              <h4 class="card-title text-sm">Inspect Sanitized AI Input Payload</h4>
            </div>
            <div class="flex items-center gap-2">
              <span class="text-xs text-muted">Schema v1.0 • Engine Authority</span>
              <span id="sanitized-chevron">${icon('chevronDown', 'w-4 h-4')}</span>
            </div>
          </div>
          <div class="sanitized-content hidden p-4" id="sanitized-content-body">
            <div class="flex justify-between items-center mb-2">
              <span class="text-xs text-muted">
                Engine guarantees: Raw IPs, SPIs, encryption keys and packet contents are stripped.
              </span>
              <button class="btn btn-ghost btn-xs" id="btn-copy-sanitized-json">
                ${icon('copy', 'w-3 h-3')} Copy JSON
              </button>
            </div>
            <pre class="code-block json-viewer" id="sanitized-json-pre">Loading sanitized data...</pre>
          </div>
        </div>
      </div>
    `;

    this.wireAiEvents();
    await this.loadAiData();
  }

  async loadAiData() {
    const contentArea = this.container.querySelector('#ai-content-area');
    const statusBadge = this.container.querySelector('#ai-job-status-badge');

    try {
      this.activeJob = await api.getJob(this.activeJobId);
      const isTerminal = ['completed', 'stopped', 'failed', 'interrupted'].includes(this.activeJob.state);

      if (statusBadge) {
        statusBadge.innerHTML = `
          State: <strong class="text-cyan font-mono uppercase">${this.activeJob.state}</strong>
        `;
      }

      // Load existing report to see if an explanation is already attached
      const report = await api.getReport(this.activeJobId).catch(() => null);
      if (report && report.ai_explanation) {
        this.aiExplanation = report.ai_explanation;
      }

      // Load sanitized AI input payload
      try {
        this.sanitizedInput = await api.getAIInput(this.activeJobId);
        const pre = this.container.querySelector('#sanitized-json-pre');
        if (pre) {
          pre.textContent = JSON.stringify(this.sanitizedInput, null, 2);
        }
      } catch (e) {
        console.warn('Failed to load AI input:', e);
      }

      if (this.aiExplanation) {
        this.renderExplanation(this.aiExplanation);
      } else if (!isTerminal) {
        contentArea.innerHTML = `
          <div class="card glass-panel p-8 text-center">
            <div class="mb-3">${icon('clock', 'w-10 h-10 text-amber mx-auto')}</div>
            <h3 class="text-lg font-bold mb-1">Capture is currently in progress</h3>
            <p class="text-muted text-sm max-w-md mx-auto mb-4">
              Per security requirements, Gemini AI analysis can only be requested after the capture job finishes to ensure complete evidence qualification.
            </p>
            <button class="btn btn-secondary btn-sm" id="btn-goto-running-job">
              ${icon('eye', 'w-4 h-4')} Monitor Live Job
            </button>
          </div>
        `;
        contentArea.querySelector('#btn-goto-running-job')?.addEventListener('click', () => {
          this.app.navigate('dashboard', { jobId: this.activeJobId });
        });
      } else {
        contentArea.innerHTML = `
          <div class="card glass-panel p-8 text-center">
            <div class="mb-3">${icon('sparkles', 'w-10 h-10 text-violet mx-auto')}</div>
            <h3 class="text-lg font-bold mb-1">No AI Explanation Generated Yet</h3>
            <p class="text-muted text-sm max-w-md mx-auto mb-6">
              Generate an executive security explanation powered by Google Gemini. The engine sends up to 30 sanitized findings without sensitive raw payloads.
            </p>
            <button class="btn btn-gradient" id="btn-generate-now">
              ${icon('sparkles', 'w-5 h-5')} Generate AI Explanation
            </button>
          </div>
        `;
        contentArea.querySelector('#btn-generate-now')?.addEventListener('click', () => {
          this.triggerExplain();
        });
      }
    } catch (err) {
      contentArea.innerHTML = `
        <div class="card glass-panel error-card p-6 text-center text-red">
          ${icon('alertTriangle', 'w-8 h-8 mx-auto mb-2')}
          <h4 class="font-bold">Failed to load job details</h4>
          <p class="text-sm text-muted mb-4">${escapeHtml(err.message)}</p>
        </div>
      `;
    }
  }

  renderExplanation(expl) {
    const contentArea = this.container.querySelector('#ai-content-area');
    if (!contentArea) return;

    if (expl.status === 'unavailable') {
      contentArea.innerHTML = `
        <div class="card glass-panel p-6 border-amber">
          <div class="flex items-center gap-3 text-amber mb-3">
            ${icon('alertTriangle', 'w-6 h-6')}
            <h3 class="font-bold text-lg">AI Explanation Unavailable</h3>
          </div>
          <p class="text-muted text-sm mb-4">
            ${escapeHtml(expl.reason || 'Gemini API key is not configured or the provider request timed out. Deterministic engine reports remain fully usable.')}
          </p>
          <div class="text-xs text-muted font-mono mb-4">
            Backend configuration required: <code>$env:GEMINI_API_KEY = "..."</code>
          </div>
          <button class="btn btn-secondary btn-sm" id="btn-retry-ai">
            ${icon('refresh', 'w-4 h-4')} Retry Explanation
          </button>
        </div>
      `;
      contentArea.querySelector('#btn-retry-ai')?.addEventListener('click', () => this.triggerExplain());
      return;
    }

    const narrative = expl.executive_summary || expl.explanation || expl.narrative || '';
    const risks = expl.risk_analysis || expl.vulnerabilities || [];
    const recommendations = expl.recommendations || expl.next_steps || [];

    contentArea.innerHTML = `
      <!-- EXECUTIVE SUMMARY CARD -->
      <div class="card glass-panel ai-summary-card mb-6">
        <div class="card-header flex items-center gap-2 mb-3">
          ${icon('sparkles', 'w-5 h-5 text-violet')}
          <h3 class="card-title">Executive AI Security Assessment</h3>
        </div>
        <div class="ai-prose-content">
          ${this.formatMarkdown(narrative)}
        </div>
      </div>

      <!-- RISK & ACTION GRID -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- RISK EVALUATION -->
        <div class="card glass-panel">
          <div class="card-header flex items-center gap-2 mb-3">
            ${icon('shieldAlert', 'w-5 h-5 text-amber')}
            <h4 class="card-title text-base">Key Risk Observations</h4>
          </div>
          <div class="ai-list-wrap">
            ${Array.isArray(risks) && risks.length > 0 ? `
              <ul class="ai-bullet-list">
                ${risks.map(r => `<li>${escapeHtml(typeof r === 'object' ? r.point || r.description : r)}</li>`).join('')}
              </ul>
            ` : `<p class="text-sm text-muted">No explicit risk points flagged by model.</p>`}
          </div>
        </div>

        <!-- REMEDIATION PRIORITIES -->
        <div class="card glass-panel">
          <div class="card-header flex items-center gap-2 mb-3">
            ${icon('checkCircle', 'w-5 h-5 text-emerald')}
            <h4 class="card-title text-base">Recommended Remediations</h4>
          </div>
          <div class="ai-list-wrap">
            ${Array.isArray(recommendations) && recommendations.length > 0 ? `
              <ul class="ai-bullet-list">
                ${recommendations.map(rc => `<li>${escapeHtml(typeof rc === 'object' ? rc.action || rc.recommendation : rc)}</li>`).join('')}
              </ul>
            ` : `<p class="text-sm text-muted">No specific remediation steps noted.</p>`}
          </div>
        </div>
      </div>
    `;
  }

  formatMarkdown(text) {
    if (!text) return '<p class="text-muted">No text available.</p>';
    // Simple fast safe markdown formatter
    let html = escapeHtml(text)
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\n\n+/g, '</p><p>')
      .replace(/\n/g, '<br>');
    return `<p>${html}</p>`;
  }

  async triggerExplain() {
    if (this.loading) return;
    this.loading = true;

    const btn = this.container.querySelector('#btn-trigger-explain');
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner-small"></span> Querying Gemini...`;
    }

    showToast('Sending sanitized findings to Gemini (max 20s timeout)...', 'info');

    try {
      const expl = await api.explainJob(this.activeJobId);
      this.aiExplanation = expl;
      this.renderExplanation(expl);
      showToast('AI analysis completed successfully!', 'success');
    } catch (err) {
      showToast(`AI explanation request failed: ${err.message}`, 'error');
      const contentArea = this.container.querySelector('#ai-content-area');
      if (contentArea) {
        contentArea.innerHTML = `
          <div class="card glass-panel error-card p-6 text-center text-red">
            ${icon('alertTriangle', 'w-8 h-8 mx-auto mb-2')}
            <h4 class="font-bold">Gemini Request Failed</h4>
            <p class="text-sm text-muted mb-4">${escapeHtml(err.message)}</p>
            <button class="btn btn-secondary btn-sm" id="btn-retry-explain-direct">Retry</button>
          </div>
        `;
        contentArea.querySelector('#btn-retry-explain-direct')?.addEventListener('click', () => this.triggerExplain());
      }
    } finally {
      this.loading = false;
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `${icon('sparkles', 'w-4 h-4')} Generate AI Analysis`;
      }
    }
  }

  wireAiEvents() {
    this.container.querySelector('#btn-trigger-explain')?.addEventListener('click', () => {
      this.triggerExplain();
    });

    this.container.querySelector('#btn-switch-ai-job')?.addEventListener('click', () => {
      this.app.navigate('jobs');
    });

    // Toggle Sanitized Input Inspector
    const toggleHeader = this.container.querySelector('#toggle-sanitized-input');
    const body = this.container.querySelector('#sanitized-content-body');
    const chevron = this.container.querySelector('#sanitized-chevron');

    toggleHeader?.addEventListener('click', () => {
      const isHidden = body.classList.contains('hidden');
      if (isHidden) {
        body.classList.remove('hidden');
        chevron.innerHTML = icon('chevronDown', 'w-4 h-4');
      } else {
        body.classList.add('hidden');
        chevron.innerHTML = icon('chevronRight', 'w-4 h-4');
      }
    });

    // Copy JSON
    this.container.querySelector('#btn-copy-sanitized-json')?.addEventListener('click', () => {
      if (this.sanitizedInput) {
        copyToClipboard(JSON.stringify(this.sanitizedInput, null, 2));
      }
    });
  }
}
