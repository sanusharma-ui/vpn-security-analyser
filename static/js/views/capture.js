/**
 * Capture & Upload Studio View
 * Supports live interface capture and binary PCAP/PCAPNG streaming upload.
 */
import { api } from '../api.js';
import { icon } from '../components/icons.js';
import { escapeHtml, showToast } from '../components/ui.js';

export class CaptureView {
  constructor(app) {
    this.app = app;
    this.container = document.getElementById('view-capture');
    this.activeTab = 'live'; // 'live' | 'pcap'
    this.interfaces = [];
    this.loadingInterfaces = false;
  }

  async render(params = {}) {
    if (params.tab) {
      this.activeTab = params.tab;
    }

    this.container.innerHTML = `
      <div class="capture-container max-w-4xl mx-auto">
        <!-- HEADER -->
        <div class="view-header mb-6 text-center">
          <h2 class="text-2xl font-bold mb-2">Capture & Analysis Studio</h2>
          <p class="text-muted">
            Acquire passive IPsec/IKE packet evidence via live network interfaces or analyze historical PCAP captures.
          </p>
        </div>

        <!-- TAB SWITCHER -->
        <div class="studio-tabs glass-panel mb-6">
          <button class="studio-tab-btn ${this.activeTab === 'live' ? 'active' : ''}" id="tab-btn-live">
            ${icon('radio', 'w-4 h-4')} Live Interface Capture
          </button>
          <button class="studio-tab-btn ${this.activeTab === 'pcap' ? 'active' : ''}" id="tab-btn-pcap">
            ${icon('upload', 'w-4 h-4')} Upload PCAP / PCAPNG
          </button>
        </div>

        <!-- TAB CONTENT AREA -->
        <div id="capture-tab-content">
          ${this.activeTab === 'live' ? this.renderLiveForm() : this.renderPcapForm()}
        </div>
      </div>
    `;

    this.wireTabEvents();
    if (this.activeTab === 'live') {
      await this.loadInterfaces();
    } else {
      this.wirePcapUploadEvents();
    }
  }

  renderLiveForm() {
    return `
      <div class="card glass-panel capture-form-card">
        <div class="card-header flex flex-wrap justify-between items-center gap-3 mb-4">
          <div class="flex items-center gap-2">
            ${icon('wifi', 'w-5 h-5 text-cyan')}
            <h3 class="card-title">Live Interface Configuration</h3>
          </div>
          <div class="flex items-center gap-2">
            <button type="button" class="btn btn-ghost btn-sm" id="btn-refresh-interfaces" title="Refresh available network interfaces">
              ${icon('refresh', 'w-4 h-4')} Refresh
            </button>
            <button type="submit" form="form-live-capture" class="btn btn-primary btn-sm" id="btn-submit-live-top">
              ${icon('play', 'w-4 h-4')} Start Live Capture
            </button>
          </div>
        </div>

        <form id="form-live-capture">
          <!-- INTERFACE SELECTOR -->
          <div class="form-group mb-5">
            <label class="form-label" for="select-interface">
              Capture Interface <span class="text-red">*</span>
            </label>
            <div class="interface-selector-wrap">
              <select class="form-control" id="select-interface" required>
                <option value="" disabled selected>Loading interfaces from backend...</option>
              </select>
            </div>
            <span class="form-hint">Choose the exact network adapter carrying the VPN tunnel traffic.</span>
          </div>

          <!-- DURATION & UPDATE INTERVAL SLIDERS -->
          <div class="form-row-2 mb-5">
            <div class="form-group">
              <div class="flex justify-between items-center mb-1">
                <label class="form-label" for="input-duration">Duration (seconds)</label>
                <span class="font-mono text-cyan font-bold" id="val-duration">60s</span>
              </div>
              <input
                type="range"
                class="form-range"
                id="input-duration"
                min="1"
                max="3600"
                value="60"
                step="1"
              />
              <span class="form-hint">Capture stops automatically when duration is reached (1–3600s).</span>
            </div>

            <div class="form-group">
              <div class="flex justify-between items-center mb-1">
                <label class="form-label" for="input-interval">Update Interval (seconds)</label>
                <span class="font-mono text-cyan font-bold" id="val-interval">2.0s</span>
              </div>
              <input
                type="range"
                class="form-range"
                id="input-interval"
                min="0.5"
                max="30"
                value="2"
                step="0.5"
              />
              <span class="form-hint">Interval between live report snapshots sent over SSE (0.5–30s).</span>
            </div>
          </div>

          <!-- PACKET LIMIT (OPTIONAL) -->
          <div class="form-group mb-5">
            <label class="form-label" for="input-packet-limit">
              Packet Limit <span class="text-muted">(Optional)</span>
            </label>
            <input
              type="number"
              class="form-control"
              id="input-packet-limit"
              placeholder="e.g. 10000 (leave empty for duration limit only)"
              min="1"
              max="1000000"
            />
            <span class="form-hint">Stops capture once this count of packets is reached (max 1,000,000).</span>
          </div>

          <!-- APPLIED BPF FILTER BANNER -->
          <div class="filter-notice-box mb-6">
            <div class="flex items-center gap-2 mb-1">
              ${icon('terminal', 'w-4 h-4 text-cyan')}
              <span class="font-mono text-xs text-muted uppercase">Pre-applied Hardware BPF Filter:</span>
            </div>
            <code class="code-block-inline">udp port 500 or udp port 4500 or esp or ah</code>
          </div>

          <!-- SUBMIT BUTTON -->
          <div class="form-actions flex justify-end">
            <button type="submit" class="btn btn-primary btn-lg" id="btn-submit-live">
              ${icon('play', 'w-5 h-5')} Start Live Capture
            </button>
          </div>
        </form>
      </div>
    `;
  }

  renderPcapForm() {
    return `
      <div class="card glass-panel capture-form-card">
        <div class="card-header flex justify-between items-center mb-4">
          <div class="flex items-center gap-2">
            ${icon('upload', 'w-5 h-5 text-cyan')}
            <h3 class="card-title">PCAP / PCAPNG File Analysis</h3>
          </div>
          <span class="text-xs font-mono text-muted">Max 50 MiB</span>
        </div>

        <!-- DRAG AND DROP ZONE -->
        <div class="pcap-dropzone" id="pcap-dropzone">
          <input type="file" id="pcap-file-input" accept=".pcap,.pcapng,.cap" style="display: none;" />
          <div class="dropzone-content">
            <div class="dropzone-icon">
              ${icon('fileCode', 'w-12 h-12 text-cyan')}
            </div>
            <h4 class="text-lg font-bold mb-1">Drag & Drop Capture File</h4>
            <p class="text-muted mb-4 text-sm">
              Supports standard PCAP and Wireshark PCAPNG capture formats.
            </p>
            <button type="button" class="btn btn-secondary" id="btn-browse-file">
              ${icon('search', 'w-4 h-4')} Browse Files
            </button>
          </div>

          <!-- SELECTED FILE PREVIEW -->
          <div class="file-preview-card hidden" id="file-preview">
            <div class="flex items-center gap-3">
              ${icon('fileCode', 'w-6 h-6 text-emerald')}
              <div>
                <div class="font-bold text-sm" id="preview-filename">file.pcap</div>
                <div class="text-xs text-muted font-mono" id="preview-filesize">0 KB</div>
              </div>
            </div>
            <button type="button" class="btn btn-ghost btn-sm" id="btn-clear-file">
              ${icon('x', 'w-4 h-4')}
            </button>
          </div>
        </div>

        <!-- UPLOAD PROGRESS -->
        <div class="upload-progress-box hidden mt-4" id="upload-progress-box">
          <div class="flex justify-between text-xs mb-1 font-mono">
            <span id="upload-status-text">Streaming binary bytes...</span>
            <span id="upload-percent-text">0%</span>
          </div>
          <div class="progress-bar-wrap">
            <div class="progress-bar-fill bg-cyan" id="upload-progress-fill" style="width: 0%"></div>
          </div>
        </div>

        <!-- SUBMIT ACTION -->
        <div class="form-actions flex justify-between items-center mt-6">
          <button type="button" class="btn btn-ghost btn-sm text-cyan" id="btn-quick-sample">
            ${icon('sparkles', 'w-4 h-4')} Load Sample (test_vpn.pcap)
          </button>

          <button type="button" class="btn btn-primary btn-lg" id="btn-upload-submit" disabled>
            ${icon('upload', 'w-5 h-5')} Upload & Analyze
          </button>
        </div>
      </div>
    `;
  }

  wireTabEvents() {
    this.container.querySelector('#tab-btn-live')?.addEventListener('click', () => {
      this.activeTab = 'live';
      this.render();
    });

    this.container.querySelector('#tab-btn-pcap')?.addEventListener('click', () => {
      this.activeTab = 'pcap';
      this.render();
    });
  }

  async loadInterfaces() {
    const select = this.container.querySelector('#select-interface');
    if (!select) return;

    this.loadingInterfaces = true;
    select.innerHTML = '<option value="" disabled selected>Enumerating interfaces via TShark/Npcap...</option>';

    try {
      const resp = await api.getInterfaces();
      this.interfaces = resp.items || [];

      if (this.interfaces.length === 0) {
        select.innerHTML = '<option value="" disabled>No capture interfaces detected on backend host.</option>';
        showToast('No capture interfaces found. Ensure Npcap/TShark is installed.', 'warning');
        return;
      }

      select.innerHTML = this.interfaces.map(iface => `
        <option value="${escapeHtml(iface.name)}">
          [#${iface.index}] ${escapeHtml(iface.name)}
        </option>
      `).join('');

      this.wireLiveFormEvents();
    } catch (err) {
      select.innerHTML = `<option value="" disabled>Interface lookup failed: ${escapeHtml(err.message)}</option>`;
      showToast(`Interface enumeration failed: ${err.message}`, 'error');
    } finally {
      this.loadingInterfaces = false;
    }
  }

  wireLiveFormEvents() {
    const form = this.container.querySelector('#form-live-capture');
    const durationInput = this.container.querySelector('#input-duration');
    const durationVal = this.container.querySelector('#val-duration');
    const intervalInput = this.container.querySelector('#input-interval');
    const intervalVal = this.container.querySelector('#val-interval');
    const refreshBtn = this.container.querySelector('#btn-refresh-interfaces');

    refreshBtn?.addEventListener('click', () => this.loadInterfaces());

    durationInput?.addEventListener('input', (e) => {
      durationVal.textContent = `${e.target.value}s`;
    });

    intervalInput?.addEventListener('input', (e) => {
      intervalVal.textContent = `${Number(e.target.value).toFixed(1)}s`;
    });

    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = this.container.querySelector('#btn-submit-live');
      const iface = this.container.querySelector('#select-interface').value;
      const duration = parseFloat(durationInput.value);
      const interval = parseFloat(intervalInput.value);
      const limitVal = this.container.querySelector('#input-packet-limit').value;
      const packetLimit = limitVal ? parseInt(limitVal, 10) : null;

      if (!iface) {
        showToast('Please select a valid network interface.', 'warning');
        return;
      }

      const submitBtnTop = this.container.querySelector('#btn-submit-live-top');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span class="spinner-small"></span> Starting Capture...`;
      }
      if (submitBtnTop) {
        submitBtnTop.disabled = true;
        submitBtnTop.innerHTML = `<span class="spinner-small"></span> Starting...`;
      }

      try {
        const payload = {
          interface: iface,
          duration_seconds: duration,
          update_interval_seconds: interval
        };
        if (packetLimit && packetLimit > 0) {
          payload.packet_limit = packetLimit;
        }

        const job = await api.startCapture(payload);
        showToast(`Live capture started successfully (Job: ${job.id.slice(0, 8)})`, 'success');
        this.app.navigate('dashboard', { jobId: job.id });
      } catch (err) {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = `${icon('play', 'w-5 h-5')} Start Live Capture`;
        }
        if (submitBtnTop) {
          submitBtnTop.disabled = false;
          submitBtnTop.innerHTML = `${icon('play', 'w-4 h-4')} Start Live Capture`;
        }
        showToast(`Failed to start capture: ${err.message}`, 'error');
      }
    });
  }

  wirePcapUploadEvents() {
    const dropzone = this.container.querySelector('#pcap-dropzone');
    const fileInput = this.container.querySelector('#pcap-file-input');
    const browseBtn = this.container.querySelector('#btn-browse-file');
    const preview = this.container.querySelector('#file-preview');
    const previewName = this.container.querySelector('#preview-filename');
    const previewSize = this.container.querySelector('#preview-filesize');
    const clearBtn = this.container.querySelector('#btn-clear-file');
    const dropContent = this.container.querySelector('.dropzone-content');
    const submitBtn = this.container.querySelector('#btn-upload-submit');
    const progressBox = this.container.querySelector('#upload-progress-box');
    const progressFill = this.container.querySelector('#upload-progress-fill');
    const percentText = this.container.querySelector('#upload-percent-text');
    const quickSampleBtn = this.container.querySelector('#btn-quick-sample');

    let selectedFile = null;

    const setFile = (file) => {
      if (!file) return;
      // 50 MiB limit
      if (file.size > 50 * 1024 * 1024) {
        showToast('Capture file exceeds the 50 MiB limit.', 'error');
        return;
      }
      selectedFile = file;
      previewName.textContent = file.name;
      previewSize.textContent = `${(file.size / (1024 * 1024)).toFixed(2)} MB`;
      dropContent.classList.add('hidden');
      preview.classList.remove('hidden');
      submitBtn.disabled = false;
    };

    const clearFile = () => {
      selectedFile = null;
      fileInput.value = '';
      dropContent.classList.remove('hidden');
      preview.classList.add('hidden');
      submitBtn.disabled = true;
    };

    browseBtn?.addEventListener('click', () => fileInput.click());
    fileInput?.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        setFile(e.target.files[0]);
      }
    });

    clearBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      clearFile();
    });

    // Drag & Drop
    ['dragenter', 'dragover'].forEach(name => {
      dropzone?.addEventListener(name, (e) => {
        e.preventDefault();
        dropzone.classList.add('drag-active');
      });
    });

    ['dragleave', 'drop'].forEach(name => {
      dropzone?.addEventListener(name, (e) => {
        e.preventDefault();
        dropzone.classList.remove('drag-active');
      });
    });

    dropzone?.addEventListener('drop', (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        setFile(e.dataTransfer.files[0]);
      }
    });

    // Quick sample loader
    quickSampleBtn?.addEventListener('click', async () => {
      try {
        quickSampleBtn.disabled = true;
        quickSampleBtn.innerHTML = `<span class="spinner-small"></span> Loading sample...`;

        // Fetch test_vpn.pcap from server static samples
        const res = await fetch('/samples/test_vpn.pcap');
        if (!res.ok) {
          throw new Error('Could not fetch test_vpn.pcap sample. Please select a local PCAP file.');
        }
        const blob = await res.blob();
        const file = new File([blob], 'test_vpn.pcap', { type: 'application/octet-stream' });
        setFile(file);
        showToast('Loaded sample test_vpn.pcap', 'success');
      } catch (err) {
        showToast(err.message, 'info');
      } finally {
        quickSampleBtn.disabled = false;
        quickSampleBtn.innerHTML = `${icon('sparkles', 'w-4 h-4')} Load Sample (test_vpn.pcap)`;
      }
    });

    // Submit Upload
    submitBtn?.addEventListener('click', async () => {
      if (!selectedFile) return;

      submitBtn.disabled = true;
      progressBox.classList.remove('hidden');

      try {
        const job = await api.uploadPcap(selectedFile, (percent) => {
          progressFill.style.width = `${percent}%`;
          percentText.textContent = `${percent}%`;
        });

        showToast('Capture uploaded successfully! Starting assessment...', 'success');
        this.app.navigate('dashboard', { jobId: job.id });
      } catch (err) {
        progressBox.classList.add('hidden');
        submitBtn.disabled = false;
        showToast(`Upload failed: ${err.message}`, 'error');
      }
    });
  }
}
