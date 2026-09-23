/** Passive evidence views. Packet-derived strings must always be escaped. */
import { escapeHtml } from './ui.js';

const text = value => escapeHtml(String(value ?? 'Unknown'));

export function renderSessionEvidence(session) {
  const timeline = session.timeline;
  const samples = session.ike_proposals || [];
  if (!timeline && !samples.length) {
    return '<p class="text-xs text-muted mt-4">Timeline and proposal detail are unavailable in this older report. Run a new analysis to collect them.</p>';
  }
  return `
    <details class="mt-4">
      <summary class="text-sm font-bold">Session timeline (${text(timeline?.events?.length || 0)} retained events)</summary>
      <p class="text-xs text-muted mt-2">${text(timeline?.meaning || 'Timeline unavailable.')}</p>
      ${timeline?.omitted_events ? `<p class="text-xs text-amber">${text(timeline.omitted_events)} earlier events omitted by the history limit.</p>` : ''}
      <div class="table-responsive mt-2"><table class="data-table">
        <thead><tr><th>Packet / capture time</th><th>Observation</th><th>Header evidence</th></tr></thead>
        <tbody>${(timeline?.events || []).map(event => {
          const detail = event.details || {};
          const direction = detail.response === true ? 'Response' : detail.response === false ? 'Request' : 'Direction unknown';
          return `<tr><td class="font-mono text-xs">#${text(event.packet_number)}<br>${text(event.timestamp)}</td>
            <td>${text(event.kind)}<br><span class="text-xs">${text(detail.exchange || detail.protocol || detail.status)}</span></td>
            <td class="text-xs">${detail.exchange ? `${text(direction)} / Message ID ${text(detail.message_id)}<br>${text(detail.src)} &rarr; ${text(detail.dst)}` : text(detail.meaning || 'Protocol observed')}
            ${(detail.notifications || []).length ? `<br>${detail.notifications.map(text).join(', ')}` : ''}
            ${detail.sequence !== undefined ? `<br>Sequence ${text(detail.sequence)}` : ''}</td></tr>`;
        }).join('') || '<tr><td colspan="3">No retained events.</td></tr>'}</tbody>
      </table></div>
    </details>
    ${samples.length ? `<details class="mt-4">
      <summary class="text-sm font-bold">IKE proposal evidence (${samples.length} packet samples)</summary>
      <p class="text-xs text-muted mt-2">Transforms and key lengths are associated using packet byte ranges. Selected IKE_SA_INIT evidence does not prove an authenticated tunnel.</p>
      ${session.proposal_samples_omitted ? `<p class="text-xs text-amber">${text(session.proposal_samples_omitted)} proposal samples omitted by retention limits.</p>` : ''}
      ${samples.map(sample => `<div class="mt-4">
        <p class="text-xs font-mono">Packet #${text(sample.packet_number)} / ${text(sample.scope)} / ${text(sample.status)}${sample.truncated ? ' / truncated' : ''}</p>
        ${(sample.reasons || []).length ? `<p class="text-xs text-amber">${sample.reasons.map(text).join(', ')}</p>` : ''}
        ${(sample.proposals || []).map(proposal => `<p class="text-sm mt-2">Proposal ${text(proposal.number)} / protocol ${text(proposal.protocol_id)}</p>
          <div class="table-responsive"><table class="data-table"><thead><tr><th>Transform type / ID</th><th>Algorithm</th><th>Key length</th><th>Byte offset</th></tr></thead>
          <tbody>${proposal.transforms.map(transform => `<tr>
            <td class="font-mono">${text(transform.type)} / ${text(transform.id)}</td><td>${text(transform.name)}</td>
            <td>${transform.key_length === null ? 'Not observed' : text(transform.key_length)}</td><td>${text(transform.byte_offset)}</td>
          </tr>`).join('')}</tbody></table></div>`).join('')}
      </div>`).join('')}
    </details>` : ''}`;
}

export function renderComparison(result) {
  const groups = [['newly_observed', 'Newly observed'], ['persistent', 'Observed in both reports'], ['no_longer_observed', 'No longer observed']];
  const metrics = Object.entries(result.scores || {}).map(([name, values]) =>
    `<span class="reason-pill">${text(name)}: ${text(values.baseline)} &rarr; ${text(values.current)} / delta ${values.delta === null ? 'unavailable' : text(values.delta)}</span>`).join(' ');
  return `<p class="text-sm mb-2">Baseline ${text(result.baseline?.job_id)} &rarr; Current ${text(result.current?.job_id)}</p>
    <p class="text-xs text-muted mb-3">No longer observed does not prove remediation. Recurring signatures may belong to different SAs.</p>
    <div class="flex flex-wrap gap-2 mb-3">${metrics}</div>
    ${(result.score_comparison_reasons || []).length ? `<p class="text-xs text-amber mb-3">Score delta unavailable: ${result.score_comparison_reasons.map(text).join(', ')}</p>` : ''}
    ${groups.map(([key, label]) => `<details class="mt-4" open><summary class="font-bold text-sm">${label} (${result[key].length})</summary>
      <div class="table-responsive mt-2"><table class="data-table"><thead><tr><th>Rule / value</th><th>Scope / status</th><th>Severity</th><th>SA count (before / after)</th></tr></thead>
      <tbody>${result[key].map(row => `<tr><td class="text-xs">${text(row.rule_id)} / ${text(row.value)}<br>${text(row.message)}</td>
        <td>${text(row.scope)} / ${text(row.status)}</td><td>${text(row.severity)}</td>
        <td>${text(row.baseline_session_count)} / ${text(row.current_session_count)}</td></tr>`).join('') || '<tr><td colspan="4">None observed.</td></tr>'}</tbody></table></div>
    </details>`).join('')}
    <details class="mt-4"><summary class="text-sm">Comparison limits</summary><ul class="text-xs text-muted">${result.limitations.map(item => `<li>${text(item)}</li>`).join('')}</ul></details>`;
}
