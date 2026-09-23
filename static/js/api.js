/**
 * API Service Client for IPsec VPN Security Analyzer
 * Handles REST endpoints, authentication (X-API-Key), binary PCAP streaming,
 * and fetch-based SSE reader.
 */

const KEY_STORAGE = 'vpn_analyzer_api_key';
const BASE_STORAGE = 'vpn_analyzer_base_url';

export class ApiClient {
  constructor() {
    this.baseUrl = localStorage.getItem(BASE_STORAGE) || window.location.origin;
    // Normalize base URL
    if (this.baseUrl.endsWith('/')) {
      this.baseUrl = this.baseUrl.slice(0, -1);
    }
  }

  getApiKey() {
    return localStorage.getItem(KEY_STORAGE) || '';
  }

  setApiKey(key) {
    if (key) {
      localStorage.setItem(KEY_STORAGE, key.trim());
    } else {
      localStorage.removeItem(KEY_STORAGE);
    }
  }

  setBaseUrl(url) {
    if (url) {
      let clean = url.trim();
      if (clean.endsWith('/')) clean = clean.slice(0, -1);
      this.baseUrl = clean;
      localStorage.setItem(BASE_STORAGE, clean);
    } else {
      this.baseUrl = window.location.origin;
      localStorage.removeItem(BASE_STORAGE);
    }
  }

  getHeaders(extra = {}) {
    const headers = { ...extra };
    const key = this.getApiKey();
    if (key) {
      headers['X-API-Key'] = key;
    }
    return headers;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = this.getHeaders(options.headers || {});

    // Default json content-type if body is object
    let body = options.body;
    if (body && typeof body === 'object' && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }

    const res = await fetch(url, {
      ...options,
      headers,
      body
    });

    if (res.status === 401) {
      const err = new Error('Unauthorized: A valid X-API-Key is required.');
      err.status = 401;
      throw err;
    }

    if (!res.ok) {
      let message = `API Error (${res.status})`;
      try {
        const data = await res.json();
        if (data.detail) {
          message = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
        }
      } catch {
        const text = await res.text();
        if (text) message = text;
      }
      const err = new Error(message);
      err.status = res.status;
      throw err;
    }

    if (res.status === 204) return null;

    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      return res.json();
    }
    return res.blob();
  }

  // System
  async getHealth() {
    // Health is public, no auth required
    const res = await fetch(`${this.baseUrl}/health`);
    if (!res.ok) throw new Error(`Health check failed (${res.status})`);
    return res.json();
  }

  // Interfaces & Policy
  async getInterfaces() {
    return this.request('/api/v1/interfaces');
  }

  async getPolicy() {
    return this.request('/api/v1/policy');
  }

  // Live Capture
  async startCapture(params) {
    return this.request('/api/v1/captures', {
      method: 'POST',
      body: params
    });
  }

  // PCAP Binary Upload (application/octet-stream)
  async uploadPcap(file, onProgress = null) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${this.baseUrl}/api/v1/analyses/pcap`);

      const key = this.getApiKey();
      if (key) {
        xhr.setRequestHeader('X-API-Key', key);
      }
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');

      if (onProgress && xhr.upload) {
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            onProgress(percent, e.loaded, e.total);
          }
        };
      }

      xhr.onload = () => {
        if (xhr.status === 202) {
          try {
            const resp = JSON.parse(xhr.responseText);
            resolve(resp);
          } catch (e) {
            resolve({ raw: xhr.responseText });
          }
        } else if (xhr.status === 401) {
          reject(new Error('Unauthorized: A valid X-API-Key is required.'));
        } else {
          let errDetail = `Upload failed (${xhr.status})`;
          try {
            const errJson = JSON.parse(xhr.responseText);
            if (errJson.detail) errDetail = errJson.detail;
          } catch {
            if (xhr.responseText) errDetail = xhr.responseText;
          }
          reject(new Error(errDetail));
        }
      };

      xhr.onerror = () => {
        reject(new Error('Network error during PCAP upload.'));
      };

      xhr.send(file);
    });
  }

  // Jobs
  async listJobs(limit = 20, offset = 0) {
    return this.request(`/api/v1/jobs?limit=${limit}&offset=${offset}`);
  }

  async getJob(id) {
    return this.request(`/api/v1/jobs/${id}`);
  }

  async stopJob(id) {
    return this.request(`/api/v1/jobs/${id}/stop`, { method: 'POST' });
  }

  async deleteJob(id) {
    return this.request(`/api/v1/jobs/${id}`, { method: 'DELETE' });
  }

  // Reports
  async getReport(id, download = false) {
    if (download) {
      const url = `${this.baseUrl}/api/v1/jobs/${id}/report?download=true`;
      const res = await fetch(url, { headers: this.getHeaders() });
      if (!res.ok) throw new Error(`Download failed (${res.status})`);
      const blob = await res.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `report-${id.slice(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(blobUrl);
      return;
    }
    return this.request(`/api/v1/jobs/${id}/report`);
  }

  async compareReports(currentId, baselineId) {
    return this.request(`/api/v1/jobs/${encodeURIComponent(currentId)}/comparison?baseline_id=${encodeURIComponent(baselineId)}`);
  }

  // AI
  async getAIInput(id) {
    return this.request(`/api/v1/jobs/${id}/ai-input`);
  }

  async explainJob(id) {
    return this.request(`/api/v1/jobs/${id}/explain`, { method: 'POST' });
  }

  /**
   * Fetch-based SSE Reader.
   * Conforms to API_HANDOFF.md requirement: browser EventSource cannot send X-API-Key.
   * Supports custom X-API-Key header, Last-Event-ID, parses snapshot and complete events.
   */
  streamJobEvents(id, { onSnapshot, onComplete, onError, onHeartbeat }) {
    const controller = new AbortController();
    let isTerminated = false;
    let lastEventId = null;

    const connect = async () => {
      try {
        const headers = this.getHeaders();
        if (lastEventId) {
          headers['Last-Event-ID'] = String(lastEventId);
        }

        const res = await fetch(`${this.baseUrl}/api/v1/jobs/${id}/events`, {
          headers,
          signal: controller.signal
        });

        if (!res.ok) {
          throw new Error(`SSE stream failed (${res.status})`);
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder('utf-8');
        let buffer = '';

        let currentEvent = 'message';
        let currentId = null;
        let currentData = '';

        while (!isTerminated) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop(); // keep partial line in buffer

          for (const line of lines) {
            const trimmed = line.trim();

            if (!trimmed) {
              // Dispatch event on empty line
              if (currentData) {
                try {
                  const parsed = JSON.parse(currentData);
                  if (currentId) lastEventId = currentId;

                  if (currentEvent === 'complete') {
                    isTerminated = true;
                    if (onComplete) onComplete(parsed);
                    return;
                  } else if (currentEvent === 'snapshot') {
                    if (onSnapshot) onSnapshot(parsed);
                  } else if (currentEvent === 'deleted') {
                    isTerminated = true;
                    if (onError) onError(new Error('Job was deleted on server.'));
                    return;
                  }
                } catch (err) {
                  console.warn('Failed to parse SSE JSON data:', currentData);
                }
              }
              currentEvent = 'message';
              currentData = '';
              currentId = null;
              continue;
            }

            if (trimmed.startsWith(':')) {
              // Comment / heartbeat
              if (onHeartbeat) onHeartbeat();
              continue;
            }

            if (trimmed.startsWith('event:')) {
              currentEvent = trimmed.slice(6).trim();
            } else if (trimmed.startsWith('id:')) {
              currentId = trimmed.slice(3).trim();
            } else if (trimmed.startsWith('data:')) {
              const d = trimmed.slice(5).trim();
              currentData = currentData ? currentData + '\n' + d : d;
            }
          }
        }
      } catch (err) {
        if (controller.signal.aborted) return;
        if (onError) onError(err);
      }
    };

    connect();

    return {
      stop: () => {
        isTerminated = true;
        controller.abort();
      }
    };
  }
}

export const api = new ApiClient();
