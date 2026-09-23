/**
 * SVG Radial Gauge Component
 * Accurately adheres to the score contract:
 * null score -> "Insufficient Evidence" (never 0 or 100)
 */

export function renderScoreGauge(score, status = 'UNKNOWN', size = 180) {
  const isNull = score === null || score === undefined;
  const numericScore = isNull ? 0 : Math.max(0, Math.min(100, Number(score)));

  // Circle dimensions
  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use a 270-degree arc for an open gauge or full 360 ring
  const strokeDashoffset = isNull ? circumference : circumference - (numericScore / 100) * circumference;

  let color = '#64748B'; // Slate neutral for null
  let glowColor = 'rgba(100, 116, 139, 0.2)';
  let ratingText = 'INSUFFICIENT EVIDENCE';

  if (!isNull) {
    if (numericScore >= 80) {
      color = '#10B981'; // Emerald
      glowColor = 'rgba(16, 185, 129, 0.35)';
      ratingText = 'EXCELLENT';
    } else if (numericScore >= 60) {
      color = '#06B6D4'; // Cyan
      glowColor = 'rgba(6, 182, 212, 0.35)';
      ratingText = 'MODERATE';
    } else if (numericScore >= 40) {
      color = '#F59E0B'; // Amber
      glowColor = 'rgba(245, 158, 11, 0.35)';
      ratingText = 'ELEVATED RISK';
    } else {
      color = '#EF4444'; // Red
      glowColor = 'rgba(239, 68, 68, 0.35)';
      ratingText = 'CRITICAL RISK';
    }
  }

  const displayScore = isNull ? '—' : numericScore;
  const subtitle = isNull ? 'Insufficient Evidence' : `${status}`;

  return `
    <div class="score-gauge-container" style="width: ${size}px; height: ${size}px;">
      <svg class="score-gauge-svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <defs>
          <filter id="gauge-glow-${size}" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="0" stdDeviation="4" flood-color="${glowColor}" />
          </filter>
        </defs>
        <!-- Background Track -->
        <circle
          class="gauge-track"
          cx="${size / 2}"
          cy="${size / 2}"
          r="${radius}"
          stroke="rgba(255, 255, 255, 0.07)"
          stroke-width="${strokeWidth}"
          fill="none"
        />
        <!-- Progress Ring -->
        <circle
          class="gauge-progress"
          cx="${size / 2}"
          cy="${size / 2}"
          r="${radius}"
          stroke="${color}"
          stroke-width="${strokeWidth}"
          stroke-linecap="round"
          stroke-dasharray="${circumference}"
          stroke-dashoffset="${strokeDashoffset}"
          fill="none"
          transform="rotate(-90 ${size / 2} ${size / 2})"
          filter="url(#gauge-glow-${size})"
        />
      </svg>
      <div class="gauge-content">
        <span class="gauge-value" style="color: ${color};">${displayScore}</span>
        <span class="gauge-max">${isNull ? '' : '/100'}</span>
        <span class="gauge-status-badge ${isNull ? 'badge-insufficient' : 'badge-provisional'}">${subtitle}</span>
      </div>
    </div>
  `;
}

export function renderMiniGauge(value, max = 100, label = '', color = '#06B6D4', size = 64) {
  const num = Math.max(0, Math.min(max, Number(value) || 0));
  const strokeWidth = 6;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (num / max) * circumference;

  return `
    <div class="mini-gauge-wrap" style="width: ${size}px; height: ${size}px;">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <circle
          cx="${size / 2}" cy="${size / 2}" r="${radius}"
          stroke="rgba(255, 255, 255, 0.08)" stroke-width="${strokeWidth}" fill="none"
        />
        <circle
          cx="${size / 2}" cy="${size / 2}" r="${radius}"
          stroke="${color}" stroke-width="${strokeWidth}" stroke-linecap="round"
          stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" fill="none"
          transform="rotate(-90 ${size / 2} ${size / 2})"
        />
      </svg>
      <div class="mini-gauge-text">
        <span>${num}%</span>
      </div>
    </div>
  `;
}
