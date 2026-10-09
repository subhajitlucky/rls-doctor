#!/usr/bin/env node
/**
 * Ecosystem study: statically analyze Supabase migration files from public
 * repositories found via GitHub code search. Aggregate, anonymized output
 * only — see docs/disclosure-policy.md.
 *
 * Usage:
 *   GITHUB_TOKEN=... node scripts/study-supabase-rls.mjs [--limit 60] [--pages 2] [--out results.json]
 *
 * Requires `npm run build` first (uses dist/index.js).
 */
import { writeFileSync } from "node:fs";
import { parseSchemaSql, analyzeCatalog } from "../dist/index.js";

const token = process.env.GITHUB_TOKEN;
if (!token) {
  console.error("study: GITHUB_TOKEN is required (public repo read scope).");
  process.exit(2);
}

const argv = process.argv.slice(2);
const flag = (name, fallback) => {
  const index = argv.indexOf(name);
  return index === -1 ? fallback : argv[index + 1];
};
const limit = Number(flag("--limit", "60"));
const pages = Number(flag("--pages", "2"));
const out = flag("--out", null);
const SEARCH_QUERY = "path:supabase/migrations extension:sql";

const headers = {
  Authorization: `Bearer ${token}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "User-Agent": "rls-doctor-study",
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function searchRepositories() {
  const repositories = new Map();
  for (let page = 1; page <= pages; page += 1) {
    const url = `https://api.github.com/search/code?q=${encodeURIComponent(SEARCH_QUERY)}&per_page=100&page=${page}`;
    const response = await fetch(url, { headers });
    if (!response.ok) {
      throw new Error(`code search failed (${response.status}): ${await response.text()}`);
    }
    const body = await response.json();
    const items = body.items ?? [];
    for (const item of items) {
      const repository = item.repository;
      if (repository === undefined || repository.fork === true) continue;
      repositories.set(repository.full_name, { fullName: repository.full_name });
    }
    if (items.length < 100) break;
    await sleep(6_500);
  }
  return [...repositories.values()].slice(0, limit);
}

async function repositoryMetadata(repository) {
  const url = `https://api.github.com/repos/${repository.fullName}`;
  const response = await fetch(url, { headers });
  if (!response.ok) throw new Error(`metadata failed (${response.status})`);
  const body = await response.json();
  return { fullName: repository.fullName, defaultBranch: body.default_branch };
}

async function migrationPaths(repository) {
  const url = `https://api.github.com/repos/${repository.fullName}/git/trees/${encodeURIComponent(repository.defaultBranch)}?recursive=1`;
  const response = await fetch(url, { headers });
  if (!response.ok) throw new Error(`tree failed (${response.status})`);
  const body = await response.json();
  return (body.tree ?? [])
    .filter((entry) =>
      entry.type === "blob" &&
      entry.path.startsWith("supabase/migrations/") &&
      entry.path.endsWith(".sql"))
    .map((entry) => entry.path)
    .sort();
}

async function fetchRaw(repository, path) {
  const url = `https://raw.githubusercontent.com/${repository.fullName}/${repository.defaultBranch}/${path}`;
  const response = await fetch(url, { headers: { "User-Agent": "rls-doctor-study" } });
  if (!response.ok) throw new Error(`raw fetch failed (${response.status})`);
  return response.text();
}

function analyzeMigrations(sql) {
  const parsed = parseSchemaSql(sql);
  const report = analyzeCatalog(parsed.snapshot, {
    schemas: parsed.schemas,
    limitations: parsed.limitations,
  });
  const findings = [...report.schemaFindings, ...report.tables.flatMap((table) => table.findings)];
  return {
    files: null,
    tables: parsed.snapshot.tables.length,
    policies: parsed.snapshot.policies.length,
    roles: parsed.snapshot.roles?.length ?? 0,
    limitations: parsed.limitations.length,
    score: report.score.value,
    findings: findings.map((finding) => ({ id: finding.id, severity: finding.severity })),
  };
}

function aggregate(records) {
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const severityCounts = Object.fromEntries(severityOrder.map((severity) => [severity, 0]));
  const ruleCounts = new Map();
  let reposWithHigh = 0;
  let reposClean = 0;
  let tables = 0;
  let policies = 0;
  let reposWithLimitations = 0;
  const scores = [];

  for (const record of records) {
    if (record.error !== undefined) continue;
    tables += record.tables;
    policies += record.policies;
    if (record.limitations > 0) reposWithLimitations += 1;
    scores.push(record.score);
    const severities = new Set();
    for (const finding of record.findings) {
      severityCounts[finding.severity] += 1;
      severities.add(finding.severity);
      if (finding.severity === "high" || finding.severity === "critical") {
        ruleCounts.set(finding.id, (ruleCounts.get(finding.id) ?? 0) + 1);
      }
    }
    if (severities.has("high") || severities.has("critical")) reposWithHigh += 1;
    if (record.findings.length === 0) reposClean += 1;
  }

  const analyzed = records.filter((record) => record.error === undefined).length;
  const failed = records.length - analyzed;
  const averageScore = scores.length === 0
    ? null
    : Math.round(scores.reduce((sum, value) => sum + value, 0) / scores.length);

  return {
    repositoriesSelected: records.length,
    repositoriesAnalyzed: analyzed,
    repositoriesFailed: failed,
    tables,
    policies,
    reposWithHighOrCritical: reposWithHigh,
    reposClean,
    reposWithLimitations,
    averageScore,
    severityCounts,
    highCriticalRules: [...ruleCounts.entries()]
      .map(([id, count]) => ({ id, count }))
      .sort((left, right) => right.count - left.count || left.id.localeCompare(right.id)),
  };
}

async function main() {
  const repositories = await searchRepositories();
  console.log(`study: ${repositories.length} repositories selected from "${SEARCH_QUERY}"`);

  const records = [];
  for (const [index, repository] of repositories.entries()) {
    const record = { index };
    try {
      const metadata = await repositoryMetadata(repository);
      const paths = await migrationPaths(metadata);
      if (paths.length === 0) {
        records.push({ ...record, error: "no migration files found" });
        continue;
      }
      const sql = (await Promise.all(paths.map((path) => fetchRaw(metadata, path)))).join("\n");
      const analysis = analyzeMigrations(sql);
      records.push({ ...record, ...analysis, files: paths.length });
      console.log(
        `study: [${index + 1}/${repositories.length}] analyzed ${paths.length} file(s): ` +
        `${analysis.tables} tables, ${analysis.findings.length} findings, score ${analysis.score}`,
      );
    } catch (error) {
      records.push({ ...record, error: error instanceof Error ? error.message : String(error) });
      console.log(`study: [${index + 1}/${repositories.length}] skipped (${records.at(-1).error})`);
    }
  }

  const summary = aggregate(records);
  console.log("\nstudy summary (aggregate, anonymized):");
  console.log(JSON.stringify(summary, null, 2));

  if (out !== null) {
    writeFileSync(out, `${JSON.stringify({ query: SEARCH_QUERY, summary, records }, null, 2)}\n`);
    console.log(`\nstudy: wrote anonymized results to ${out}`);
  }
}

await main();
