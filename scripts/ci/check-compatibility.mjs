#!/usr/bin/env node
// FULL (backward and forward) compatibility gate for event payload schemas.
// Status: Proposed (API Governance Guild review required). Policy: compatibility/POLICY.md.
//
// Usage: BASE_REF=origin/main node scripts/ci/check-compatibility.mjs
//
// Every schemas/**/*.schema.json that exists at the merge base of BASE_REF (default origin/main) and HEAD is
// compared with the working tree using the rules in scripts/ci/lib/compat-rules.mjs. New files (including a
// new major version .v<N+1>) are skipped. Deleted files are breaking. Findings listed in
// compatibility/accepted-breaking.txt (one key per line, '#' comments) are reported but do not fail.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { checkFileChange, readAccepted, filterAccepted } from './lib/compat-rules.mjs';

const git = (args) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const baseRef = process.env.BASE_REF || 'origin/main';

try {
  git(['rev-parse', '--verify', '--quiet', `${baseRef}^{commit}`]);
} catch {
  console.error(`BASE_REF ${baseRef} is not available. Fetch full history (actions/checkout fetch-depth: 0) or set BASE_REF.`);
  process.exit(2);
}
let base = baseRef;
try {
  base = git(['merge-base', baseRef, 'HEAD']).trim();
} catch {
  // unrelated histories: compare with the ref itself
}

const isSchema = (f) => /^schemas\/.+\.schema\.json$/.test(f);
const baseFiles = git(['ls-tree', '-r', '--name-only', base, '--', 'schemas']).split('\n').filter(isSchema);
const accepted = readAccepted(fs.existsSync('compatibility/accepted-breaking.txt') ? fs.readFileSync('compatibility/accepted-breaking.txt', 'utf8') : '');

console.log(`schema compatibility check (FULL): base ${baseRef} (merge base ${base.slice(0, 12)}), ${baseFiles.length} schema(s) at base`);
let failed = 0;
let changed = 0;
for (const rel of baseFiles.sort()) {
  const baseText = git(['show', `${base}:${rel}`]);
  const headText = fs.existsSync(rel) ? fs.readFileSync(rel, 'utf8') : null;
  if (headText === baseText) continue;
  changed++;
  let findings;
  try {
    findings = checkFileChange(rel, baseText, headText);
  } catch (e) {
    console.error(`ERR ${rel}: ${e.message}`);
    failed++;
    continue;
  }
  const { open, accepted: ok } = filterAccepted(findings, accepted);
  ok.forEach((f) => console.log(`accepted ${f.key}`));
  open.forEach((f) => console.error(`BREAKING ${f.key}  (${f.detail})`));
  if (open.length === 0) console.log(`ok   ${rel}: ${ok.length > 0 ? `${ok.length} accepted finding(s), no open findings` : 'compatible change'}`);
  failed += open.length;
}
if (failed > 0) {
  console.error(`schema compatibility check failed: ${failed} finding(s). Publish a new major version as a new file (.v<N+1>) on a new topic with dual-publish, or record an approved exception in compatibility/accepted-breaking.txt.`);
  process.exit(1);
}
console.log(`schema compatibility check passed: ${changed} changed schema(s), no open findings`);
