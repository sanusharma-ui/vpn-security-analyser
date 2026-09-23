import test from 'node:test';
import assert from 'node:assert/strict';
import { renderSessionEvidence, renderComparison } from '../static/js/components/investigation.js';

globalThis.localStorage = { getItem() { return null; } };
globalThis.window = { location: { origin: 'http://localhost' } };
const { api } = await import('../static/js/api.js');
const { JobsView } = await import('../static/js/views/jobs.js');
const attack = '<img src=x onerror="alert(1)">';

function comparison() {
  return {baseline: {job_id: 'baseline'}, current: {job_id: 'current'},
    scores: {security_score: {baseline: null, current: 100, delta: null}},
    newly_observed: [{rule_id: 'ENC-004', value: attack, scope: 'offered', status: 'FAIL',
      severity: 'critical', message: attack, baseline_session_count: 0, current_session_count: 1}],
    persistent: [], no_longer_observed: [], score_comparison_reasons: ['baseline_evidence_not_score_eligible'],
    limitations: [attack]};
}

test('timeline escapes packet evidence and preserves unknown direction and suspected semantics', () => {
  const html = renderSessionEvidence({timeline: {events: [{kind: 'IKE_MESSAGE', packet_number: 4,
    timestamp: attack, details: {exchange: 'IKE_AUTH', src: attack, dst: 'b', response: null,
      notifications: [attack]}}], omitted_events: 7, meaning: 'Observed headers only.'}});
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(html.includes('Direction unknown'));
  assert.ok(html.includes('7 earlier events omitted'));
  assert.ok(html.includes('IKE_AUTH'));
});

test('proposal view preserves unavailable evidence and escapes algorithms', () => {
  const html = renderSessionEvidence({ike_proposals: [{packet_number: 1, scope: 'offered', status: 'PARTIAL',
    truncated: true, reasons: ['ambiguous_key_length'], proposals: [{number: 1, protocol_id: 1,
      transforms: [{type: 1, id: 20, name: attack, key_length: null, byte_offset: 112}]}]}]});
  assert.ok(html.includes('Not observed'));
  assert.ok(html.includes('PARTIAL / truncated'));
  assert.ok(!html.includes('<img'));
  assert.ok(renderSessionEvidence({}).includes('older report'));
});

test('comparison renders null as unknown, not zero, and keeps scope and limitations', () => {
  const html = renderComparison(comparison());
  assert.ok(html.includes('Unknown &rarr; 100 / delta unavailable'));
  assert.ok(html.includes('offered / FAIL'));
  assert.ok(html.includes('No longer observed does not prove remediation'));
  assert.ok(!html.includes('<img'));
});

function view() {
  const elements = {
    '#comparison-baseline': {value: 'baseline'}, '#comparison-current': {value: 'current'},
    '#btn-compare-reports': {disabled: false}, '#comparison-result': {innerHTML: '', textContent: ''},
  };
  const instance = Object.create(JobsView.prototype);
  instance.container = {querySelector: key => elements[key]};
  return {instance, elements};
}

test('comparison client calls the authenticated read-only route', async () => {
  const original = api.request;
  try {
    api.request = async endpoint => { assert.equal(endpoint, '/api/v1/jobs/current/comparison?baseline_id=baseline'); return comparison(); };
    assert.equal((await api.compareReports('current', 'baseline')).current.job_id, 'current');
  } finally { api.request = original; }
});

test('comparison action renders data and recovers from a server conflict', async () => {
  const {instance, elements} = view();
  const original = api.compareReports;
  try {
    api.compareReports = async (current, baseline) => {
      assert.equal(current, 'current'); assert.equal(baseline, 'baseline'); return comparison();
    };
    await instance.compareSelected();
    assert.ok(elements['#comparison-result'].innerHTML.includes('ENC-004'));
    assert.equal(elements['#btn-compare-reports'].disabled, false);
    api.compareReports = async () => { throw new Error('Both jobs must have a saved report.'); };
    await instance.compareSelected();
    assert.ok(elements['#comparison-result'].textContent.includes('Comparison unavailable'));
    assert.equal(elements['#btn-compare-reports'].disabled, false);
  } finally { api.compareReports = original; }
});

test('late responses cannot overwrite a changed selection or destroyed view', async () => {
  const {instance, elements} = view();
  const original = api.compareReports;
  let resolve;
  try {
    api.compareReports = () => new Promise(done => { resolve = done; });
    const pending = instance.compareSelected();
    instance.destroy();
    elements['#comparison-result'].innerHTML = 'new selection';
    resolve(comparison());
    await pending;
    assert.equal(elements['#comparison-result'].innerHTML, 'new selection');
  } finally { api.compareReports = original; }
});

test('selection rejects identical reports and filters unfinished jobs', async () => {
  const {instance, elements} = view();
  const original = api.listJobs;
  try {
    api.listJobs = async () => ({items: [
      {id: 'finished', state: 'completed', summary: {}, created_at: '2026-09-23T00:00:00Z'},
      {id: 'active', state: 'running', summary: {}, created_at: '2026-09-23T00:00:00Z'},
      {id: 'empty', state: 'failed', summary: null, created_at: '2026-09-23T00:00:00Z'},
    ]});
    await instance.loadComparisonChoices();
    assert.ok(elements['#comparison-baseline'].innerHTML.includes('finished'));
    assert.ok(!elements['#comparison-baseline'].innerHTML.includes('active'));
    assert.ok(!elements['#comparison-baseline'].innerHTML.includes('empty'));
    elements['#comparison-baseline'].value = 'same';
    elements['#comparison-current'].value = 'same';
    elements['#comparison-baseline'].onchange();
    assert.equal(elements['#btn-compare-reports'].disabled, true);
  } finally { api.listJobs = original; }
});


test('dashboard builds evidence only after expanding a session', async () => {
  const { DashboardView } = await import('../static/js/views/dashboard.js');
  const content = {innerHTML: ''};
  let toggle;
  const element = {open: false, dataset: {sessionIndex: '0'},
    querySelector() { return content; }, addEventListener(name, callback) { toggle = callback; }};
  const dashboard = Object.create(DashboardView.prototype);
  dashboard.container = {
    querySelectorAll(name) { return name === '.session-evidence' ? [element] : []; },
    querySelector() { return null; },
  };
  dashboard.activeReport = {sessions: [{session_id: 'test-sa', timeline: {events: [], meaning: 'Passive'}}]};
  dashboard.evidenceOpen = new Set();
  dashboard.wireDashboardEvents();
  assert.equal(content.innerHTML, '');
  element.open = true;
  toggle();
  assert.ok(content.innerHTML.includes('Session timeline'));
  assert.ok(dashboard.evidenceOpen.has('test-sa'));
  element.open = false;
  toggle();
  assert.ok(!dashboard.evidenceOpen.has('test-sa'));
});
