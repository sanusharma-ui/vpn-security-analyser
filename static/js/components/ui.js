/**
 * UI Utilities, Toasts, Modals and Formatting Helpers.
 */
import { icon } from './icons.js';

// Toast Center
export function showToast(message, type = 'info', duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type} slide-in-bottom`;

  const iconName = type === 'success' ? 'checkCircle' :
                   type === 'error' ? 'alertCircle' :
                   type === 'warning' ? 'alertTriangle' : 'info';

  toast.innerHTML = `
    <span class="toast-icon">${icon(iconName, 'w-5 h-5')}</span>
    <span class="toast-message">${escapeHtml(message)}</span>
    <button class="toast-close" aria-label="Close">${icon('x', 'w-4 h-4')}</button>
  `;

  const removeToast = () => {
    toast.classList.add('toast-fade-out');
    setTimeout(() => toast.remove(), 250);
  };

  toast.querySelector('.toast-close').addEventListener('click', removeToast);
  container.appendChild(toast);

  if (duration > 0) {
    setTimeout(removeToast, duration);
  }
}

// Modal Dialog
export function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
  }
}

export function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('active');
    document.body.style.overflow = '';
  }
}

// Confirm Dialog
export function confirmAction(title, message, confirmText = 'Confirm', isDanger = false) {
  return new Promise((resolve) => {
    let modal = document.getElementById('confirm-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'confirm-modal';
      modal.className = 'modal-backdrop';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="modal-card">
        <div class="modal-header">
          <h3 class="modal-title">${escapeHtml(title)}</h3>
          <button class="modal-close" id="confirm-modal-x">${icon('x', 'w-5 h-5')}</button>
        </div>
        <div class="modal-body">
          <p>${escapeHtml(message)}</p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" id="confirm-modal-cancel">Cancel</button>
          <button class="btn ${isDanger ? 'btn-danger' : 'btn-primary'}" id="confirm-modal-proceed">
            ${escapeHtml(confirmText)}
          </button>
        </div>
      </div>
    `;

    modal.classList.add('active');

    const cleanup = (result) => {
      modal.classList.remove('active');
      resolve(result);
    };

    modal.querySelector('#confirm-modal-x').onclick = () => cleanup(false);
    modal.querySelector('#confirm-modal-cancel').onclick = () => cleanup(false);
    modal.querySelector('#confirm-modal-proceed').onclick = () => cleanup(true);
  });
}

// Copy to Clipboard
export async function copyToClipboard(text, triggerBtn = null) {
  try {
    await navigator.clipboard.writeText(text);
    if (triggerBtn) {
      const originalHTML = triggerBtn.innerHTML;
      triggerBtn.innerHTML = `${icon('check', 'w-4 h-4 text-emerald')} Copied!`;
      triggerBtn.disabled = true;
      setTimeout(() => {
        triggerBtn.innerHTML = originalHTML;
        triggerBtn.disabled = false;
      }, 1800);
    }
    showToast('Copied to clipboard', 'success', 2000);
  } catch (err) {
    showToast('Failed to copy to clipboard', 'error');
  }
}

// Formatters
export function escapeHtml(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function formatTimestamp(isoStr) {
  if (!isoStr) return '—';
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  } catch {
    return isoStr;
  }
}

export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  const sec = Math.round(Number(seconds));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const rem = sec % 60;
  return `${m}m ${rem}s`;
}

export function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function formatScoreReason(reason) {
  const map = {
    no_assessable_sessions: 'No assessable IPsec sessions detected',
    selected_cipher_not_observed: 'Selected encryption cipher not observed in handshake',
    selected_sa_identity_unavailable: 'Selected SA identity unavailable or anonymous',
    selected_encryption_unassessed: 'Selected encryption cipher unassessed',
    selected_key_length_unassessed: 'Key length unassessed or undetermined',
    selected_prf_unassessed: 'Selected PRF algorithm unassessed',
    selected_dh_group_unassessed: 'Diffie-Hellman group unassessed',
    selected_integrity_unassessed: 'Integrity algorithm unassessed',
    incomplete_supported_checks: 'Incomplete supported crypto checks',
    observations_truncated: 'Packet observations truncated by engine bounds',
    one_or_more_sessions_unassessed: 'One or more retained SAs could not be assessed',
    sessions_evicted: 'Active session capacity reached; sessions were evicted',
    capture_queue_drops: 'Packet drops detected in capture queue',
    capture_incomplete: 'Capture stopped prematurely or encountered an error'
  };
  return map[reason] || reason.replace(/_/g, ' ');
}

export function getSeverityBadge(severity) {
  const sev = (severity || 'info').toLowerCase();
  const classes = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info'
  };
  return `<span class="badge ${classes[sev] || 'badge-info'}">${sev.toUpperCase()}</span>`;
}

export function getStatusBadge(status) {
  const st = (status || 'unknown').toUpperCase();
  const classes = {
    PASS: 'badge-pass',
    FAIL: 'badge-fail',
    SUSPECTED: 'badge-suspected',
    UNKNOWN: 'badge-unknown',
    NOT_APPLICABLE: 'badge-na'
  };
  return `<span class="badge ${classes[st] || 'badge-unknown'}">${st}</span>`;
}

export function getJobStateBadge(state) {
  const s = (state || 'unknown').toLowerCase();
  const isRunning = s === 'running' || s === 'queued';
  const isStopping = s === 'stopping';
  const isSuccess = s === 'completed';
  const isFail = s === 'failed' || s === 'interrupted';

  let badgeClass = 'badge-secondary';
  let pulse = '';

  if (isRunning) {
    badgeClass = 'badge-running';
    pulse = '<span class="status-pulse-dot"></span>';
  } else if (isStopping) {
    badgeClass = 'badge-stopping';
  } else if (isSuccess) {
    badgeClass = 'badge-completed';
  } else if (isFail) {
    badgeClass = 'badge-failed';
  } else if (s === 'stopped') {
    badgeClass = 'badge-stopped';
  }

  return `<span class="badge ${badgeClass}">${pulse}${s.toUpperCase()}</span>`;
}
