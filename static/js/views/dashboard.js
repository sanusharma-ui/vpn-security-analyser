/**
 * Live Analysis & Overview Dashboard View
 */
import { api } from '../api.js';
import { renderSessionEvidence } from '../components/investigation.js';
import { icon } from '../components/icons.js';
import { renderScoreGauge, renderMiniGauge } from '../components/gauge.js';
import {
  escapeHtml,
  formatTimestamp,
  formatScoreReason,
  getSeverityBadge,
  getStatusBadge,
  getJobStateBadge,
  copyToClipboard,
  showToast,
  confirmAction
} from '../components/ui.js';

export class DashboardView {
  constructor(app) {
    this.app = app;
    this.container = document.getElementById('view-dashboard');
    this.activeJobId = null;
    this.activeJob = null;
    this.activeReport = null;
    this.sseStream = null;
    this.pollInterval = null;
    this.severityFilter = 'all';
    this.statusFilter = 'all';
    this.searchQuery = '';
    this.evidenceOpen = new Set();
  }

  async render(params = null) {
    const passedId = typeof params === 'string' ? params : (params && typeof params === 'object' ? params.jobId : null);
    if (passedId) {
      this.activeJobId = passedId;
    }

    if (!this.activeJobId) {
      // If no active job specified, find the most recent job
      try {
        const jobs = await api.listJobs(1, 0);
        if (jobs.items && jobs.items.length > 0) {
          this.activeJobId = jobs.items[0].id;
        }
      } catch (e) {
        // API key might not be set yet or no jobs exist
      }
    }

    if (!this.activeJobId) {
      this.renderEmptyState();
      return;
    }

    const shortId = typeof this.activeJobId === 'string' ? this.activeJobId.slice(0, 8) : '...';
    this.container.innerHTML = `
      <div class="dashboard-loading-state p-12 text-center text-muted">
        <span class="spinner-large mb-3"></span>
        <p>Loading security assessment for job <code class="code-mono">${shortId}</code>...</p>
      </div>
    `;

    await this.loadJobData();
  }

  renderEmptyState() {
    this.container.innerHTML = `
      <div class="card empty-state-card glass-panel max-w-3xl mx-auto text-center p-8">
        <div class="empty-state-icon mb-4">
          ${icon('shield', 'w-16 h-16 text-cyan mx-auto')}
        </div>
        <h2 class="text-2xl font-bold mb-2">Passive IPsec Security Monitor</h2>
        <p class="text-muted max-w-lg mx-auto mb-6 text-sm">
          Real-time deterministic assessment for IPsec/IKE tunnels. Start a live network capture, upload a PCAP file, or launch an instant demo with the included sample capture.
        </p>

        <!-- INSTANT DEMO CTA -->
        <div class="demo-cta-box glass-panel p-4 mb-6" style="border: 1px solid rgba(6, 182, 212, 0.4); background: rgba(6, 182, 212, 0.04);">
          <div class="flex flex-wrap items-center justify-between gap-4">
            <div class="text-left">
              <div class="flex items-center gap-2 mb-1">
                <span class="badge badge-provisional">INSTANT DEMO</span>
                <strong class="text-white">Sample VPN Capture (test_vpn.pcap)</strong>
              </div>
              <p class="text-xs text-muted">
                One-click full assessment: IKEv2 handshake, ciphers, DH groups, risk scores, and findings.
              </p>
            </div>
            <button class="btn btn-primary" id="btn-run-demo-instant">
              ${icon('sparkles', 'w-4 h-4')} Analyze Sample Now
            </button>
          </div>
        </div>

        <!-- ACTION BUTTONS -->
        <div class="empty-state-actions flex justify-center gap-4">
          <button class="btn btn-secondary" id="btn-empty-start-capture">
            ${icon('play', 'w-4 h-4')} Start Live Capture
          </button>
          <button class="btn btn-secondary" id="btn-empty-upload-pcap">
            ${icon('upload', 'w-4 h-4')} Upload Custom PCAP
          </button>
        </div>
      </div>
    `;

    // Wire events
    this.container.querySelector('#btn-run-demo-instant')?.addEventListener('click', async () => {
      const btn = this.container.querySelector('#btn-run-demo-instant');
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner-small"></span> Analyzing Sample...`;
      showToast('Uploading and analyzing test_vpn.pcap sample...', 'info');

      try {
        const res = await fetch('/samples/test_vpn.pcap');
        if (!res.ok) throw new Error('Sample file /samples/test_vpn.pcap not found.');
        const blob = await res.blob();
        const file = new File([blob], 'test_vpn.pcap', { type: 'application/octet-stream' });
        const job = await api.uploadPcap(file);
        showToast('Sample analyzed successfully! Loading dashboard...', 'success');
        this.render({ jobId: job.id });
      } catch (err) {
        btn.disabled = false;
        btn.innerHTML = `${icon('sparkles', 'w-4 h-4')} Analyze Sample Now`;
        showToast(`Failed to run sample: ${err.message}`, 'error');
      }
    });

    this.container.querySelector('#btn-empty-start-capture')?.addEventListener('click', () => {
      this.app.navigate('capture', { tab: 'live' });
    });
    this.container.querySelector('#btn-empty-upload-pcap')?.addEventListener('click', () => {
      this.app.navigate('capture', { tab: 'pcap' });
    });
  }

  async loadJobData() {
    try {
      this.activeJob = await api.getJob(this.activeJobId);

      // Try to get current report
      try {
        this.activeReport = await api.getReport(this.activeJobId);
      } catch (e) {
        this.activeReport = null;
      }

      this.renderDashboardContent();
      this.handleStreamSubscription();
    } catch (err) {
      this.container.innerHTML = `
        <div class="card glass-panel error-card">
          <div class="flex items-center gap-3 text-red mb-3">
            ${icon('alertTriangle', 'w-6 h-6')}
            <h3>Failed to load job data</h3>
          </div>
          <p class="text-muted mb-4">${escapeHtml(err.message)}</p>
          <div class="flex gap-3">
            <button class="btn btn-secondary" id="btn-dashboard-retry">
              ${icon('refresh', 'w-4 h-4')} Retry
            </button>
            <button class="btn btn-primary" id="btn-dashboard-switch-view">
              ${icon('list', 'w-4 h-4')} View All Jobs
            </button>
          </div>
        </div>
      `;

      this.container.querySelector('#btn-dashboard-retry')?.addEventListener('click', () => this.render(this.activeJobId));
      this.container.querySelector('#btn-dashboard-switch-view')?.addEventListener('click', () => this.app.navigate('jobs'));
    }
  }

  handleStreamSubscription() {
    // Clear previous streams
    if (this.sseStream) {
      this.sseStream.stop();
      this.sseStream = null;
    }
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }

    const state = this.activeJob?.state;
    const isTerminal = ['completed', 'stopped', 'failed', 'interrupted'].includes(state);

    if (isTerminal) {
      this.updateStreamIndicator('Complete', 'neutral');
      return;
    }

    this.updateStreamIndicator('Connecting SSE...', 'running');

    // Subscribe to SSE
    this.sseStream = api.streamJobEvents(this.activeJobId, {
      onSnapshot: async (data) => {
        this.updateStreamIndicator('Live Streaming', 'active');
        if (data.state) this.activeJob.state = data.state;
        if (data.summary) {
          if (!this.activeReport) this.activeReport = { summary: data.summary };
          else this.activeReport.summary = data.summary;
        }
        // Fetch full report on update if needed
        try {
          this.activeReport = await api.getReport(this.activeJobId);
          this.renderDashboardContent();
        } catch {
          this.renderDashboardContent();
        }
      },
      onComplete: async (data) => {
        this.updateStreamIndicator('Assessment Complete', 'success');
        if (data.state) this.activeJob.state = data.state;
        try {
          this.activeReport = await api.getReport(this.activeJobId);
        } catch {}
        this.renderDashboardContent();
        showToast('Capture job reached completion', 'info');
      },
      onError: (err) => {
        console.warn('SSE disconnected, falling back to polling:', err);
        this.updateStreamIndicator('Polling Fallback', 'warning');
        this.startPollingFallback();
      },
      onHeartbeat: () => {
        // Keep-alive pulse
      }
    });
  }

  startPollingFallback() {
    if (this.pollInterval) clearInterval(this.pollInterval);
    this.pollInterval = setInterval(async () => {
      try {
        const job = await api.getJob(this.activeJobId);
        this.activeJob = job;
        const rep = await api.getReport(this.activeJobId);
        this.activeReport = rep;
        this.renderDashboardContent();

        if (['completed', 'stopped', 'failed', 'interrupted'].includes(job.state)) {
          clearInterval(this.pollInterval);
          this.pollInterval = null;
          this.updateStreamIndicator('Complete', 'neutral');
        }
      } catch (e) {
        // Suppress polling error
      }
    }, 2000);
  }

  updateStreamIndicator(text, type = 'neutral') {
    const el = document.getElementById('dashboard-stream-badge');
    if (el) {
      el.className = `stream-badge stream-${type}`;
      el.innerHTML = `<span class="pulse-dot"></span> ${escapeHtml(text)}`;
    }
  }

  renderDashboardContent() {
    const job = this.activeJob;
    const report = this.activeReport;
    const summary = report?.summary || job?.summary || {};
    const traffic = report?.traffic || {};
    const crypto = report?.crypto || {};
    const metadata = report?.metadata || {};
    const findings = report?.findings || [];
    const sessions = report?.sessions || [];
    const reasons = summary.score_reasons || [];
    const isRunning = job?.state === 'running' || job?.state === 'queued';
    const isStopping = job?.state === 'stopping';

    // Compliance
    const compliance = report?.compliance || { nist_sp_800_77_rev1: 'UNKNOWN', cnsa_2_0: 'UNKNOWN' };

    this.container.innerHTML = `
      <!-- TOP STATUS & CONTROL BAR -->
      <div class="dashboard-topbar glass-panel mb-6">
        <div class="topbar-left">
          <div class="flex items-center gap-2">
            <span class="text-xs uppercase font-mono tracking-wider text-muted">Active Job:</span>
            <code class="code-badge" id="btn-copy-job-id" title="Click to copy Job ID">
              ${job.id} ${icon('copy', 'w-3 h-3 inline ml-1')}
            </code>
          </div>
          <div class="flex items-center gap-2 mt-1">
            <span class="source-tag source-${job.source_type}">
              ${icon(job.source_type === 'live' ? 'radio' : 'fileCode', 'w-3 h-3 inline')}
              ${job.source_type.toUpperCase()}
            </span>
            ${getJobStateBadge(job.state)}
            <span id="dashboard-stream-badge" class="stream-badge stream-neutral">
              <span class="pulse-dot"></span> In Sync
            </span>
          </div>
        </div>

        <div class="topbar-actions">
          ${isRunning ? `
            <button class="btn btn-danger btn-sm" id="btn-stop-capture">
              ${icon('square', 'w-4 h-4')} Stop Capture
            </button>
          ` : isStopping ? `
            <button class="btn btn-secondary btn-sm" disabled>
              <span class="spinner-small"></span> Stopping...
            </button>
          ` : ''}

          <button class="btn btn-secondary btn-sm" id="btn-download-report" title="Download JSON Report">
            ${icon('download', 'w-4 h-4')} Export Report
          </button>

          <button class="btn btn-gradient btn-sm" id="btn-ai-explain" title="Generate Gemini AI Analysis">
            ${icon('sparkles', 'w-4 h-4')} AI Analysis
          </button>
        </div>
      </div>

      <!-- MAIN METRICS & SCORE GRID -->
      <div class="metrics-hero-grid mb-6">
        <!-- SCORE GAUGE CARD -->
        <div class="card glass-panel score-hero-card">
          <div class="card-header flex justify-between items-center">
            <div class="flex items-center gap-2">
              ${icon('shield', 'w-5 h-5 text-cyan')}
              <h3 class="card-title">Security Assessment</h3>
            </div>
            <span class="text-xs text-muted font-mono" title="Scores are strictly provisional passive measurements">
              ${summary.assessment_status || 'PROVISIONAL'}
            </span>
          </div>

          <div class="score-card-body">
            <div class="gauge-wrapper">
              ${renderScoreGauge(summary.security_score, summary.assessment_status, 170)}
            </div>

            <div class="score-details-list">
              <div class="score-detail-row">
                <span class="detail-label">Confirmed Risk Level</span>
                <span class="risk-pill risk-${(summary.risk_level || 'UNKNOWN').toLowerCase()}">
                  ${summary.risk_level || 'UNKNOWN'} (${summary.risk_score !== undefined && summary.risk_score !== null ? summary.risk_score : '—'})
                </span>
              </div>

              <div class="score-detail-row">
                <span class="detail-label">Crypto Checks Coverage</span>
                <div class="flex items-center gap-2">
                  <div class="progress-bar-wrap w-24">
                    <div class="progress-bar-fill bg-cyan" style="width: ${summary.assessment_coverage || 0}%"></div>
                  </div>
                  <span class="font-mono text-sm">${summary.assessment_coverage || 0}%</span>
                </div>
              </div>

              <div class="score-detail-row">
                <span class="detail-label">VPN Protocol</span>
                <span class="font-mono text-sm text-cyan font-bold">${summary.protocol || 'None Detected'}</span>
              </div>
            </div>
          </div>

          <!-- SCORE SUPPRESSION REASONS (if any) -->
          ${reasons.length > 0 ? `
            <div class="score-reasons-box">
              <div class="reasons-header">
                ${icon('info', 'w-3.5 h-3.5 text-amber')}
                <span>Score Suppression Factors (${reasons.length})</span>
              </div>
              <div class="reasons-pills">
                ${reasons.map(r => `<span class="reason-pill" title="${r}">${formatScoreReason(r)}</span>`).join('')}
              </div>
            </div>
          ` : ''}
        </div>

        <!-- TRAFFIC & HEALTH STATS -->
        <div class="traffic-stats-column">
          <div class="stats-mini-grid">
            <div class="card glass-panel stat-card">
              <div class="stat-icon-wrap bg-blue-subtle">
                ${icon('activity', 'w-5 h-5 text-blue')}
              </div>
              <div class="stat-content">
                <span class="stat-label">Total Packets</span>
                <span class="stat-value font-mono">${(traffic.packets_processed || 0).toLocaleString()}</span>
              </div>
            </div>

            <div class="card glass-panel stat-card">
              <div class="stat-icon-wrap bg-cyan-subtle">
                ${icon('shieldCheck', 'w-5 h-5 text-cyan')}
              </div>
              <div class="stat-content">
                <span class="stat-label">Security Packets</span>
                <span class="stat-value font-mono">${(traffic.security_packets || 0).toLocaleString()}</span>
              </div>
            </div>

            <div class="card glass-panel stat-card">
              <div class="stat-icon-wrap bg-violet-subtle">
                ${icon('database', 'w-5 h-5 text-violet')}
              </div>
              <div class="stat-content">
                <span class="stat-label">Retained SAs</span>
                <span class="stat-value font-mono">${sessions.length}</span>
              </div>
            </div>

            <div class="card glass-panel stat-card">
              <div class="stat-icon-wrap ${traffic.queue_drops > 0 ? 'bg-red-subtle' : 'bg-emerald-subtle'}">
                ${icon(traffic.queue_drops > 0 ? 'alertTriangle' : 'checkCircle', `w-5 h-5 ${traffic.queue_drops > 0 ? 'text-red' : 'text-emerald'}`)}
              </div>
              <div class="stat-content">
                <span class="stat-label">Queue Drops</span>
                <span class="stat-value font-mono ${traffic.queue_drops > 0 ? 'text-red font-bold' : ''}">
                  ${(traffic.queue_drops || 0).toLocaleString()}
                </span>
              </div>
            </div>
          </div>

          <!-- COMPLIANCE REFERENCE CARD -->
          <div class="card glass-panel compliance-card mt-3">
            <div class="card-header flex justify-between items-center py-2">
              <h4 class="text-xs uppercase font-mono tracking-wider text-muted">Government & Industry Baselines</h4>
              <span class="text-xs text-muted">Passive check limitation</span>
            </div>
            <div class="compliance-row">
              <div class="compliance-item">
                <span class="compliance-name">NIST SP 800-77 Rev 1</span>
                <span class="compliance-val badge badge-unknown">${compliance.nist_sp_800_77_rev1 || 'UNKNOWN'}</span>
              </div>
              <div class="compliance-item">
                <span class="compliance-name">CNSA 2.0 Quantum-Resistant</span>
                <span class="compliance-val badge badge-unknown">${compliance.cnsa_2_0 || 'UNKNOWN'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- CRYPTOGRAPHIC PARAMETERS SUITE -->
      <div class="card glass-panel mb-6">
        <div class="card-header flex justify-between items-center">
          <div class="flex items-center gap-2">
            ${icon('lock', 'w-5 h-5 text-cyan')}
            <h3 class="card-title">Active Cryptographic Suite</h3>
          </div>
          <span class="text-xs text-muted font-mono">IKE / IPsec Security Association Parameters</span>
        </div>

        <div class="crypto-parameters-grid">
          <div class="crypto-box">
            <span class="crypto-label">Protocol & Version</span>
            <span class="crypto-val">${crypto.ike_version ? `IKEv${crypto.ike_version}` : 'Undetected'}</span>
          </div>

          <div class="crypto-box">
            <span class="crypto-label">Encryption Cipher</span>
            <span class="crypto-val ${crypto.encryption ? 'text-emerald' : 'text-muted'}">
              ${crypto.encryption || 'Unobserved'}
            </span>
          </div>

          <div class="crypto-box">
            <span class="crypto-label">Key Length</span>
            <span class="crypto-val font-mono">${crypto.key_length ? `${crypto.key_length} bits` : '—'}</span>
          </div>

          <div class="crypto-box">
            <span class="crypto-label">Integrity Algorithm</span>
            <span class="crypto-val font-mono">${crypto.integrity || '—'}</span>
          </div>

          <div class="crypto-box">
            <span class="crypto-label">Pseudo-Random Function (PRF)</span>
            <span class="crypto-val font-mono">${crypto.prf || '—'}</span>
          </div>

          <div class="crypto-box">
            <span class="crypto-label">Diffie-Hellman Group</span>
            <span class="crypto-val font-mono">${crypto.dh_group_name || (crypto.dh_group ? `Group ${crypto.dh_group}` : '—')}</span>
          </div>

          <div class="crypto-box">
            <span class="crypto-label">ESP SPI (Hex)</span>
            <span class="crypto-val font-mono text-xs">${report?.protocol?.esp_spi || '—'}</span>
          </div>

          <div class="crypto-box">
            <span class="crypto-label">NAT-Traversal (NAT-T)</span>
            <span class="crypto-val font-mono">
              ${report?.protocol?.natt_detected ? `<span class="text-amber">${icon('check', 'w-3 h-3 inline')} Active (Port 4500)</span>` : 'Inactive'}
            </span>
          </div>
        </div>
      </div>

      <!-- FINDINGS & VULNERABILITIES EXPLORER -->
      <div class="card glass-panel mb-6">
        <div class="card-header flex flex-wrap justify-between items-center gap-3">
          <div class="flex items-center gap-2">
            ${icon('shieldAlert', 'w-5 h-5 text-amber')}
            <h3 class="card-title">Security Findings & Engine Rules</h3>
            <span class="count-badge">${findings.length}</span>
          </div>

          <div class="findings-filter-controls flex flex-wrap items-center gap-2">
            <!-- Search -->
            <div class="search-input-wrap">
              ${icon('search', 'search-icon w-4 h-4')}
              <input
                type="text"
                class="search-input"
                id="findings-search"
                placeholder="Search rule ID, message..."
                value="${escapeHtml(this.searchQuery)}"
              />
            </div>

            <!-- Severity Filter -->
            <select class="select-dropdown" id="findings-severity-select">
              <option value="all" ${this.severityFilter === 'all' ? 'selected' : ''}>All Severities</option>
              <option value="critical" ${this.severityFilter === 'critical' ? 'selected' : ''}>Critical Only</option>
              <option value="high" ${this.severityFilter === 'high' ? 'selected' : ''}>High Only</option>
              <option value="medium" ${this.severityFilter === 'medium' ? 'selected' : ''}>Medium Only</option>
              <option value="low" ${this.severityFilter === 'low' ? 'selected' : ''}>Low Only</option>
              <option value="info" ${this.severityFilter === 'info' ? 'selected' : ''}>Info Only</option>
            </select>

            <!-- Status Filter -->
            <select class="select-dropdown" id="findings-status-select">
              <option value="all" ${this.statusFilter === 'all' ? 'selected' : ''}>All Statuses</option>
              <option value="FAIL" ${this.statusFilter === 'FAIL' ? 'selected' : ''}>Failures (FAIL)</option>
              <option value="PASS" ${this.statusFilter === 'PASS' ? 'selected' : ''}>Passed (PASS)</option>
              <option value="UNKNOWN" ${this.statusFilter === 'UNKNOWN' ? 'selected' : ''}>Unknown (UNKNOWN)</option>
              <option value="SUSPECTED" ${this.statusFilter === 'SUSPECTED' ? 'selected' : ''}>Suspected</option>
            </select>
          </div>
        </div>

        <div class="findings-list" id="findings-list-container">
          ${this.renderFilteredFindings(findings)}
        </div>
      </div>

      <!-- RETAINED SECURITY ASSOCIATIONS (SAs) -->
      ${sessions.length > 0 ? `
        <div class="card glass-panel mb-6">
          <div class="card-header flex justify-between items-center">
            <div class="flex items-center gap-2">
              ${icon('cpu', 'w-5 h-5 text-cyan')}
              <h3 class="card-title">Retained Security Associations (${sessions.length})</h3>
            </div>
            <span class="text-xs text-muted">Passive SA state tracking</span>
          </div>

          <div class="sessions-accordion">
            ${sessions.map((sa, idx) => `
              <div class="session-card">
                <div class="session-header">
                  <div class="flex items-center gap-3">
                    <span class="session-index font-mono">#${idx + 1}</span>
                    <code class="session-id font-mono text-sm">${escapeHtml(sa.session_id)}</code>
                  </div>
                  <div class="flex items-center gap-3">
                    <span class="text-xs text-muted font-mono">Coverage: ${sa.confidence?.coverage || 0}%</span>
                    <span class="badge ${sa.risk?.security_score !== null ? 'badge-provisional' : 'badge-insufficient'}">
                      Score: ${sa.risk?.security_score !== null ? sa.risk.security_score : 'Insufficient Evidence'}
                    </span>
                  </div>
                </div>

                ${sa.score_reasons && sa.score_reasons.length > 0 ? `
                  <div class="session-reasons">
                    ${sa.score_reasons.map(r => `<span class="reason-pill text-xs">${formatScoreReason(r)}</span>`).join('')}
                  </div>
                ` : ''}
                <details class="mt-4 session-evidence" data-session-index="${idx}" ${this.evidenceOpen.has(sa.session_id) ? 'open' : ''}>
                  <summary class="text-sm font-bold">Inspect timeline and proposal evidence</summary>
                  <div class="session-evidence-content"></div>
                </details>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}
    `;

    this.wireDashboardEvents();
  }

  renderFilteredFindings(findings) {
    const q = this.searchQuery.toLowerCase().trim();
    const filtered = findings.filter(f => {
      if (this.severityFilter !== 'all' && (f.severity || 'info').toLowerCase() !== this.severityFilter) {
        return false;
      }
      if (this.statusFilter !== 'all' && (f.status || 'unknown') !== this.statusFilter) {
        return false;
      }
      if (q) {
        const text = `${f.rule_id || ''} ${f.description || ''} ${f.parameter || ''} ${f.message || ''} ${f.recommendation || ''}`.toLowerCase();
        if (!text.includes(q)) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      return `
        <div class="empty-findings-state p-6 text-center text-muted">
          ${icon('checkCircle', 'w-8 h-8 mx-auto mb-2 text-emerald')}
          <p>No findings matching the selected filters.</p>
        </div>
      `;
    }

    return filtered.map(f => {
      const isFail = f.status === 'FAIL';
      const isPass = f.status === 'PASS';
      return `
        <div class="finding-card ${isFail ? 'finding-fail' : isPass ? 'finding-pass' : 'finding-neutral'}">
          <div class="finding-main-row">
            <div class="finding-badges">
              ${getStatusBadge(f.status)}
              ${getSeverityBadge(f.severity)}
              <span class="scope-tag font-mono text-xs">${escapeHtml(f.scope || 'observed')}</span>
            </div>
            <div class="finding-id-area">
              <span class="rule-id font-mono font-bold">${escapeHtml(f.rule_id || 'RULE')}</span>
              <span class="finding-desc">${escapeHtml(f.description || f.parameter || '')}</span>
            </div>
          </div>

          ${f.evidence && f.evidence.length > 0 ? `
            <div class="finding-evidence">
              <span class="evidence-title">Observed Evidence:</span>
              <ul class="evidence-list">
                ${f.evidence.map(e => `<li><code>${escapeHtml(typeof e === 'object' ? JSON.stringify(e) : String(e))}</code></li>`).join('')}
              </ul>
            </div>
          ` : ''}

          ${f.recommendation ? `
            <div class="finding-recommendation">
              ${icon('sparkles', 'w-4 h-4 text-cyan inline mr-1')}
              <span><strong>Recommendation:</strong> ${escapeHtml(f.recommendation)}</span>
            </div>
          ` : ''}
        </div>
      `;
    }).join('');
  }

  wireDashboardEvents() {
    this.container.querySelectorAll('.session-evidence').forEach(element => {
      const session = this.activeReport?.sessions?.[Number(element.dataset.sessionIndex)];
      if (!session) return;
      const populate = () => {
        if (element.open) {
          this.evidenceOpen.add(session.session_id);
          if (!element.dataset.loaded) {
            element.querySelector('.session-evidence-content').innerHTML = renderSessionEvidence(session);
            element.dataset.loaded = 'true';
          }
        } else {
          this.evidenceOpen.delete(session.session_id);
        }
      };
      element.addEventListener('toggle', populate);
      if (element.open) populate();
    });
    // Copy Job ID
    this.container.querySelector('#btn-copy-job-id')?.addEventListener('click', () => {
      copyToClipboard(this.activeJob.id);
    });

    // Stop Capture
    this.container.querySelector('#btn-stop-capture')?.addEventListener('click', async () => {
      const ok = await confirmAction('Stop Capture', 'Are you sure you want to request stopping this active capture? Partial evidence will be saved.', 'Stop Capture', true);
      if (!ok) return;

      try {
        await api.stopJob(this.activeJob.id);
        showToast('Stop request submitted. Polling until terminal state...', 'info');
        this.activeJob.state = 'stopping';
        this.renderDashboardContent();
      } catch (err) {
        showToast(`Failed to stop capture: ${err.message}`, 'error');
      }
    });

    // Download JSON Report
    this.container.querySelector('#btn-download-report')?.addEventListener('click', async () => {
      try {
        await api.getReport(this.activeJob.id, true);
        showToast('Downloading JSON report...', 'success');
      } catch (err) {
        showToast(`Failed to export report: ${err.message}`, 'error');
      }
    });

    // AI Analysis trigger
    this.container.querySelector('#btn-ai-explain')?.addEventListener('click', () => {
      this.app.navigate('ai', { jobId: this.activeJob.id });
    });

    // Filter controls
    const searchInput = this.container.querySelector('#findings-search');
    searchInput?.addEventListener('input', (e) => {
      this.searchQuery = e.target.value;
      this.updateFindingsList();
    });

    const sevSelect = this.container.querySelector('#findings-severity-select');
    sevSelect?.addEventListener('change', (e) => {
      this.severityFilter = e.target.value;
      this.updateFindingsList();
    });

    const statusSelect = this.container.querySelector('#findings-status-select');
    statusSelect?.addEventListener('change', (e) => {
      this.statusFilter = e.target.value;
      this.updateFindingsList();
    });
  }

  updateFindingsList() {
    const list = this.container.querySelector('#findings-list-container');
    if (list && this.activeReport) {
      list.innerHTML = this.renderFilteredFindings(this.activeReport.findings || []);
    }
  }

  destroy() {
    if (this.sseStream) {
      this.sseStream.stop();
      this.sseStream = null;
    }
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }
}
