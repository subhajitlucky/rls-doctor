import type { AuditReport } from "../audit/types.js";

export const RLS_SCORE_LABEL = "RLS Score";

export interface ScoreRenderOptions {
  score?: boolean;
  badge?: boolean;
}

export function renderScoreLine(report: AuditReport): string {
  return `${RLS_SCORE_LABEL}: ${report.score.value}/100\n`;
}

export function scoreBadgeUrl(report: AuditReport): string {
  const label = encodeURIComponent(RLS_SCORE_LABEL);
  return `https://img.shields.io/badge/${label}-${report.score.value}%2F100-${report.score.band}`;
}

/**
 * `--score` prints the RLS Score, `--badge` prints a shields.io badge URL.
 * Both derive from the same deterministic report score; neither replaces the
 * full report's evidence.
 */
export function renderScoreOutput(
  report: AuditReport,
  options: ScoreRenderOptions
): string | undefined {
  const lines: string[] = [];
  if (options.score === true) lines.push(renderScoreLine(report).trimEnd());
  if (options.badge === true) lines.push(scoreBadgeUrl(report));
  return lines.length === 0 ? undefined : `${lines.join("\n")}\n`;
}
