/**
 * Jobs & History Explorer View
 * Manages past analysis jobs with filtering, pagination, inspection, report download, and deletion.
 */
import { api } from '../api.js';
import { renderComparison } from '../components/investigation.js';
import { icon } from '../components/icons.js';
import {
  escapeHtml,
  formatTimestamp,
  getJobStateBadge,
  copyToClipboard,
  showToast,
  confirmAction
} from '../components/ui.js';

export class JobsView {
  constructor(app) {
    this.app = app;
    this.container = document.getElementById('view-jobs');
    this.limit = 20;
    this.offset = 0;
    this.total = 0;
    this.items = [];
    this.filterState = 'all';
  }

  async render() {
    this.container.innerHTML = `
      <div class="jobs-view-container max-w-6xl mx-auto">
        <!-- HEADER -->
        <div class="view-header flex flex-wrap justify-between items-center gap-4 mb-6">
          <div>
            <h2 class="text-2xl font-bold mb-1">Assessment History & Jobs</h2>
            <p class="text-muted text-sm">
              Explore past capture analyses, inspect findings, download reports, or reclaim capacity.
            </p>
          </div>

          <div class="flex items-center gap-3">
            <button class="btn btn-secondary btn-sm" id="btn-refresh-jobs">
              ${icon('refresh', 'w-4 h-4')} Refresh
            </button>
            <button class="btn btn-primary btn-sm" id="btn-new-job">
              ${icon('play', 'w-4 h-4')} New Capture
            </button>
          </div>
        </div>

        <section class="card glass-panel mb-6 p-4" aria-labelledby="comparison-title">
          <h3 id="comparison-title" class="font-bold mb-2">Compare saved assessments</h3>
          <p class="text-xs text-muted mb-3">Choose two finished reports. Changes describe retained observations; missing findings do not prove a fix.</p>
          <div class="flex flex-wrap items-center gap-3">
            <label class="text-sm">Baseline <select id="comparison-baseline" class="select-dropdown"><option value="">Loading...</option></select></label>
            <label class="text-sm">Current <select id="comparison-current" class="select-dropdown"><option value="">Loading...</option></select></label>
            <button id="btn-compare-reports" class="btn btn-secondary btn-sm" disabled>Compare reports</button>
          </div>
          <div id="comparison-result" class="mt-4" aria-live="polite"></div>
        </section>

        <!-- FILTERS & STATS -->
        <div class="card glass-panel mb-6 p-4 flex flex-wrap justify-between items-center gap-4">
          <div class="filter-pills flex items-center gap-2">
            <button class="filter-pill ${this.filterState === 'all' ? 'active' : ''}" data-state="all">All Jobs</button>
            <button class="filter-pill ${this.filterState === 'running' ? 'active' : ''}" data-state="running">Running</button>
            <button class="filter-pill ${this.filterState === 'completed' ? 'active' : ''}" data-state="completed">Completed</button>
            <button class="filter-pill ${this.filterState === 'stopped' ? 'active' : ''}" data-state="stopped">Stopped</button>
            <button class="filter-pill ${this.filterState === 'failed' ? 'active' : ''}" data-state="failed">Failed</button>
          </div>

          <div class="text-sm text-muted font-mono" id="jobs-count-text">
            Loading jobs...
          </div>
        </div>

        <!-- JOBS TABLE CONTAINER -->
        <div class="card glass-panel overflow-hidden" id="jobs-table-wrap">
          <div class="table-loading p-8 text-center text-muted">
            <span class="spinner-large mb-3"></span>
            <p>Fetching analysis jobs from server...</p>
          </div>
        </div>

        <!-- PAGINATION BAR -->
        <div class="pagination-bar flex justify-between items-center mt-4">
          <span class="text-xs text-muted font-mono" id="pagination-info">Page 1</span>
          <div class="flex items-center gap-2">
            <button class="btn btn-secondary btn-sm" id="btn-prev-page" disabled>Previous</button>
            <button class="btn btn-secondary btn-sm" id="btn-next-page" disabled>Next</button>
          </div>
        </div>
      </div>
    `;

    this.wireStaticEvents();
    await this.loadJobs();
    await this.loadComparisonChoices();
  }

  wireStaticEvents() {
    this.container.querySelector('#btn-refresh-jobs')?.addEventListener('click', () => { this.loadJobs(); this.loadComparisonChoices(); });
    this.container.querySelector('#btn-compare-reports')?.addEventListener('click', () => this.compareSelected());
    this.container.querySelector('#btn-new-job')?.addEventListener('click', () => this.app.navigate('capture'));

    this.container.querySelectorAll('.filter-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        this.container.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.filterState = btn.dataset.state;
        this.renderTable();
      });
    });

    this.container.querySelector('#btn-prev-page')?.addEventListener('click', () => {
      if (this.offset >= this.limit) {
        this.offset -= this.limit;
        this.loadJobs();
      }
    });

    this.container.querySelector('#btn-next-page')?.addEventListener('click', () => {
      if (this.offset + this.limit < this.total) {
        this.offset += this.limit;
        this.loadJobs();
      }
    });
  }

  async loadJobs() {
    try {
      const resp = await api.listJobs(this.limit, this.offset);
      this.items = resp.items || [];
      this.total = resp.total || 0;

      const countEl = this.container.querySelector('#jobs-count-text');
      if (countEl) {
        countEl.textContent = `Total: ${this.total} jobs (Allowance: 100 max)`;
      }

      this.updatePagination();
      this.renderTable();
    } catch (err) {
      const wrap = this.container.querySelector('#jobs-table-wrap');
      if (wrap) {
        wrap.innerHTML = `
          <div class="p-8 text-center text-red">
            ${icon('alertTriangle', 'w-8 h-8 mx-auto mb-2 text-red')}
            <h4 class="font-bold mb-1">Failed to retrieve jobs</h4>
            <p class="text-sm text-muted mb-4">${escapeHtml(err.message)}</p>
            <button class="btn btn-secondary btn-sm" id="btn-retry-fetch-jobs">Retry</button>
          </div>
        `;
        wrap.querySelector('#btn-retry-fetch-jobs')?.addEventListener('click', () => this.loadJobs());
      }
    }
  }

  async loadComparisonChoices() {
    const baseline = this.container.querySelector('#comparison-baseline');
    const current = this.container.querySelector('#comparison-current');
    const button = this.container.querySelector('#btn-compare-reports');
    if (!baseline || !current || !button) return;
    button.disabled = true;
    const request = this.choiceRequest = (this.choiceRequest || 0) + 1;
    this.comparisonRequest = (this.comparisonRequest || 0) + 1;
    this.container.querySelector('#comparison-result').textContent = '';
    try {
      const jobs = await api.listJobs(100, 0);
      if (request !== this.choiceRequest) return;
      const finished = (jobs.items || []).filter(job => ['completed', 'stopped', 'failed', 'interrupted'].includes(job.state) && job.summary);
      const options = '<option value="">Select a report</option>' + finished.map(job =>
        `<option value="${escapeHtml(job.id)}">${escapeHtml(job.id.slice(0, 8))} / ${escapeHtml(job.state)} / ${escapeHtml(formatTimestamp(job.created_at))}</option>`).join('');
      baseline.innerHTML = options;
      current.innerHTML = options;
      const update = () => {
        button.disabled = !baseline.value || !current.value || baseline.value === current.value;
        this.container.querySelector('#comparison-result').textContent = '';
        this.comparisonRequest = (this.comparisonRequest || 0) + 1;
      };
      baseline.onchange = update;
      current.onchange = update;
      update();
      if (finished.length < 2) this.container.querySelector('#comparison-result').textContent = 'Two finished reports are needed for comparison.';
    } catch (error) {
      if (request !== this.choiceRequest) return;
      baseline.innerHTML = current.innerHTML = '<option value="">Unavailable</option>';
      this.container.querySelector('#comparison-result').textContent = `Could not load reports: ${error.message}`;
    }
  }

  async compareSelected() {
    const baseline = this.container.querySelector('#comparison-baseline').value;
    const current = this.container.querySelector('#comparison-current').value;
    if (!baseline || !current || baseline === current) return;
    const output = this.container.querySelector('#comparison-result');
    const button = this.container.querySelector('#btn-compare-reports');
    const request = this.comparisonRequest = (this.comparisonRequest || 0) + 1;
    button.disabled = true;
    output.textContent = 'Comparing saved evidence...';
    try {
      const result = await api.compareReports(current, baseline);
      if (request === this.comparisonRequest) output.innerHTML = renderComparison(result);
    } catch (error) {
      if (request === this.comparisonRequest) output.textContent = `Comparison unavailable: ${error.message}`;
    } finally {
      if (request === this.comparisonRequest) button.disabled = false;
    }
  }

  destroy() {
    this.choiceRequest = (this.choiceRequest || 0) + 1;
    this.comparisonRequest = (this.comparisonRequest || 0) + 1;
  }

  updatePagination() {
    const info = this.container.querySelector('#pagination-info');
    const prev = this.container.querySelector('#btn-prev-page');
    const next = this.container.querySelector('#btn-next-page');

    const start = this.total > 0 ? this.offset + 1 : 0;
    const end = Math.min(this.offset + this.limit, this.total);

    if (info) info.textContent = `Showing ${start}–${end} of ${this.total}`;
    if (prev) prev.disabled = this.offset === 0;
    if (next) next.disabled = this.offset + this.limit >= this.total;
  }

  renderTable() {
    const wrap = this.container.querySelector('#jobs-table-wrap');
    if (!wrap) return;

    let displayItems = this.items;
    if (this.filterState !== 'all') {
      displayItems = this.items.filter(j => j.state === this.filterState);
    }

    if (displayItems.length === 0) {
      wrap.innerHTML = `
        <div class="empty-table-state p-12 text-center text-muted">
          ${icon('database', 'w-10 h-10 mx-auto mb-2 opacity-50')}
          <h4 class="font-bold mb-1">No jobs match the criteria</h4>
          <p class="text-sm">Run a live capture or upload a PCAP file to start assessing.</p>
        </div>
      `;
      return;
    }

    wrap.innerHTML = `
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Job ID</th>
              <th>Type</th>
              <th>Status</th>
              <th>Created At</th>
              <th>Security Score</th>
              <th>Risk Level</th>
              <th class="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${displayItems.map(j => {
              const summary = j.summary || {};
              const score = summary.security_score;
              const hasScore = score !== null && score !== undefined;
              const risk = summary.risk_level || '—';

              return `
                <tr class="job-row" data-id="${j.id}">
                  <td>
                    <div class="flex items-center gap-2">
                      <code class="code-badge font-mono text-xs" title="${j.id}">
                        ${j.id.slice(0, 8)}...
                      </code>
                      <button class="btn-icon-tiny btn-copy-id" data-id="${j.id}" title="Copy full ID">
                        ${icon('copy', 'w-3 h-3')}
                      </button>
                    </div>
                  </td>
                  <td>
                    <span class="source-tag source-${j.source_type}">
                      ${icon(j.source_type === 'live' ? 'radio' : 'fileCode', 'w-3 h-3 inline')}
                      ${j.source_type.toUpperCase()}
                    </span>
                  </td>
                  <td>${getJobStateBadge(j.state)}</td>
                  <td class="font-mono text-xs text-muted">${formatTimestamp(j.created_at)}</td>
                  <td>
                    <span class="badge ${hasScore ? 'badge-provisional' : 'badge-insufficient'} font-mono">
                      ${hasScore ? `${score}/100` : 'Insufficient Evidence'}
                    </span>
                  </td>
                  <td>
                    <span class="risk-pill risk-${risk.toLowerCase()}">${risk}</span>
                  </td>
                  <td class="text-right">
                    <div class="flex items-center justify-end gap-1">
                      <button class="btn btn-ghost btn-xs btn-inspect-job" data-id="${j.id}" title="Inspect in Dashboard">
                        ${icon('eye', 'w-4 h-4')}
                      </button>
                      <button class="btn btn-ghost btn-xs btn-download-job" data-id="${j.id}" title="Download JSON Report">
                        ${icon('download', 'w-4 h-4')}
                      </button>
                      <button class="btn btn-ghost btn-xs text-violet btn-ai-job" data-id="${j.id}" title="Gemini AI Analysis">
                        ${icon('sparkles', 'w-4 h-4')}
                      </button>
                      <button class="btn btn-ghost btn-xs text-red btn-delete-job" data-id="${j.id}" title="Delete Finished Job">
                        ${icon('trash', 'w-4 h-4')}
                      </button>
                    </div>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;

    this.wireTableActions();
  }

  wireTableActions() {
    // Copy ID
    this.container.querySelectorAll('.btn-copy-id').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(btn.dataset.id);
      });
    });

    // Inspect Job
    this.container.querySelectorAll('.btn-inspect-job').forEach(btn => {
      btn.addEventListener('click', () => {
        this.app.navigate('dashboard', { jobId: btn.dataset.id });
      });
    });

    // Row click
    this.container.querySelectorAll('.job-row').forEach(row => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('button') || e.target.closest('a')) return;
        this.app.navigate('dashboard', { jobId: row.dataset.id });
      });
    });

    // Download Report
    this.container.querySelectorAll('.btn-download-job').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        try {
          await api.getReport(btn.dataset.id, true);
          showToast('Downloading report...', 'success');
        } catch (err) {
          showToast(`Export failed: ${err.message}`, 'error');
        }
      });
    });

    // AI Analysis
    this.container.querySelectorAll('.btn-ai-job').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.app.navigate('ai', { jobId: btn.dataset.id });
      });
    });

    // Delete Job
    this.container.querySelectorAll('.btn-delete-job').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id = btn.dataset.id;
        const ok = await confirmAction(
          'Delete Finished Job',
          `Are you sure you want to permanently delete job ${id.slice(0, 8)}...? This reclaims server storage capacity.`,
          'Delete Job',
          true
        );
        if (!ok) return;

        try {
          await api.deleteJob(id);
          showToast('Job deleted successfully', 'success');
          await this.loadJobs();
          await this.loadComparisonChoices();
        } catch (err) {
          showToast(`Failed to delete job: ${err.message}`, 'error');
        }
      });
    });
  }
}
