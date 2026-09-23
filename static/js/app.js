/**
 * Main Application Orchestrator
 * Controls navigation, header state, API key modal, and view lifecycles.
 */
import { api } from './api.js';
import { icon } from './components/icons.js';
import { showToast, openModal, closeModal } from './components/ui.js';
import { DashboardView } from './views/dashboard.js';
import { CaptureView } from './views/capture.js';
import { JobsView } from './views/jobs.js';
import { AiView } from './views/ai.js';
import { PolicyView } from './views/policy.js';

class Application {
  constructor() {
    this.currentView = null;
    this.views = {};
    this.activeJobBeacon = null;
    this.healthInterval = null;
  }

  async init() {
    // Instantiate Views
    this.views = {
      dashboard: new DashboardView(this),
      capture: new CaptureView(this),
      jobs: new JobsView(this),
      ai: new AiView(this),
      policy: new PolicyView(this)
    };

    this.wireNavigation();
    this.wireKeySettings();
    this.wireMobileMenu();
    this.startHealthMonitor();

    // Check if API key is configured
    this.updateKeyStatusBadge();

    // Initial Route based on Hash or default to dashboard
    this.handleRoute();
    window.addEventListener('hashchange', () => this.handleRoute());

    // Prompt for API key on first launch if unset
    if (!api.getApiKey()) {
      setTimeout(() => {
        openModal('modal-api-key');
      }, 600);
    }
  }

  navigate(viewName, params = {}) {
    let hash = `#${viewName}`;
    const searchParams = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) {
        searchParams.set(k, v);
      }
    }
    const queryString = searchParams.toString();
    if (queryString) {
      hash += `?${queryString}`;
    }
    window.location.hash = hash;
  }

  handleRoute() {
    const rawHash = window.location.hash.slice(1) || 'dashboard';
    const [viewName, query] = rawHash.split('?');
    const params = {};
    if (query) {
      const sp = new URLSearchParams(query);
      for (const [k, v] of sp.entries()) {
        params[k] = v;
      }
    }

    const targetView = this.views[viewName] ? viewName : 'dashboard';
    this.switchView(targetView, params);
  }

  switchView(name, params = {}) {
    // Teardown previous view if needed
    if (this.currentView && typeof this.views[this.currentView]?.destroy === 'function') {
      this.views[this.currentView].destroy();
    }

    // Hide all view containers
    document.querySelectorAll('.view-panel').forEach(panel => {
      panel.classList.remove('active');
    });

    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
      if (link.dataset.view === name) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Close mobile menu
    document.getElementById('sidebar')?.classList.remove('mobile-open');

    // Show target view container
    const panel = document.getElementById(`view-${name}`);
    if (panel) {
      panel.classList.add('active');
      this.currentView = name;
      this.views[name].render(params);
    }
  }

  wireNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const view = link.dataset.view;
        if (view) this.navigate(view);
      });
    });

    document.getElementById('btn-header-new-capture')?.addEventListener('click', () => {
      this.navigate('capture');
    });
  }

  wireMobileMenu() {
    const toggle = document.getElementById('mobile-menu-toggle');
    const sidebar = document.getElementById('sidebar');
    toggle?.addEventListener('click', () => {
      sidebar?.classList.toggle('mobile-open');
    });

    // Backdrop click
    document.getElementById('sidebar-backdrop')?.addEventListener('click', () => {
      sidebar?.classList.remove('mobile-open');
    });
  }

  wireKeySettings() {
    const trigger = document.getElementById('btn-key-settings');
    const modal = document.getElementById('modal-api-key');
    const closeBtn = document.getElementById('modal-api-key-close');
    const saveBtn = document.getElementById('btn-save-key');
    const testBtn = document.getElementById('btn-test-key');
    const inputKey = document.getElementById('input-api-key');
    const inputBase = document.getElementById('input-base-url');
    const toggleMask = document.getElementById('btn-toggle-mask-key');

    trigger?.addEventListener('click', () => {
      inputKey.value = api.getApiKey();
      inputBase.value = api.baseUrl;
      openModal('modal-api-key');
    });

    closeBtn?.addEventListener('click', () => closeModal('modal-api-key'));

    // Toggle Eye Mask
    toggleMask?.addEventListener('click', () => {
      if (inputKey.type === 'password') {
        inputKey.type = 'text';
        toggleMask.innerHTML = icon('eyeOff', 'w-4 h-4');
      } else {
        inputKey.type = 'password';
        toggleMask.innerHTML = icon('eye', 'w-4 h-4');
      }
    });

    // Test Connection
    testBtn?.addEventListener('click', async () => {
      const originalHtml = testBtn.innerHTML;
      testBtn.disabled = true;
      testBtn.innerHTML = `<span class="spinner-small"></span> Testing...`;

      const tempKey = inputKey.value.trim();
      const tempUrl = inputBase.value.trim();
      api.setApiKey(tempKey);
      api.setBaseUrl(tempUrl);

      try {
        await api.getInterfaces();
        showToast('Authentication successful! Backend is connected.', 'success');
        this.updateKeyStatusBadge();
      } catch (err) {
        showToast(`Connection test failed: ${err.message}`, 'error');
      } finally {
        testBtn.disabled = false;
        testBtn.innerHTML = originalHtml;
      }
    });

    // Save
    saveBtn?.addEventListener('click', () => {
      const key = inputKey.value.trim();
      const url = inputBase.value.trim();
      api.setApiKey(key);
      api.setBaseUrl(url);
      closeModal('modal-api-key');
      this.updateKeyStatusBadge();
      showToast('API credentials saved', 'success');

      // Re-render current view with new credentials
      this.handleRoute();
    });
  }

  updateKeyStatusBadge() {
    const key = api.getApiKey();
    const badge = document.getElementById('header-key-badge');
    if (!badge) return;

    if (key) {
      badge.className = 'key-status-badge key-set';
      badge.innerHTML = `${icon('key', 'w-3.5 h-3.5')} <span>Key Configured</span>`;
      badge.title = 'Click to manage API Key';
    } else {
      badge.className = 'key-status-badge key-missing';
      badge.innerHTML = `${icon('alertTriangle', 'w-3.5 h-3.5')} <span>Set API Key</span>`;
      badge.title = 'API Key required for analysis endpoints';
    }
  }

  startHealthMonitor() {
    const check = async () => {
      const badge = document.getElementById('system-health-badge');
      if (!badge) return;

      try {
        const health = await api.getHealth();
        badge.className = 'health-badge health-online';
        badge.innerHTML = `<span class="status-pulse-dot"></span> Backend v${health.version || '0.5.0'}`;
      } catch {
        badge.className = 'health-badge health-offline';
        badge.innerHTML = `<span class="offline-dot"></span> Backend Offline`;
      }
    };

    check();
    this.healthInterval = setInterval(check, 10000);
  }
}

// Global App Bootstrapper
document.addEventListener('DOMContentLoaded', () => {
  const app = new Application();
  app.init();
  window.__vpn_app = app;
});
