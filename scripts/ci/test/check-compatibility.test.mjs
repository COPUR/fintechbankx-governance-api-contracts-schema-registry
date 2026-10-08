// Fixture pairs for the backward-compatibility rules (scripts/ci/test/fixtures/compat/<case>/{base,head}.schema.json).
// Each breaking-* case must produce exactly its rule; each compatible-* case must produce no finding.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkFileChange, readAccepted, filterAccepted } from '../lib/compat-rules.mjs';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'compat');
const REL = 'schemas/tst/sample/created.v1.schema.json';
const run = (name) => {
  const read = (f) => fs.readFileSync(path.join(FIXTURES, name, f), 'utf8');
  return checkFileChange(REL, read('base.schema.json'), read('head.schema.json'));
};
const keys = (findings) => findings.map((f) => f.key);

const breaking = {
  'breaking-removed-property': [`removed-property ${REL} $.note`],
  'breaking-removed-nested-property': [`removed-property ${REL} $.amount.currency`],
  'breaking-newly-required': [`newly-required ${REL} $.note`],
  'breaking-new-required-property': [`newly-required ${REL} $.channel`],
  'breaking-type-change': [`changed-type ${REL} $.note`],
  'breaking-enum-value-removed': [`removed-enum-value ${REL} $.status "CLOSED"`],
  'breaking-additional-properties-tightened': [`tightened-additional-properties ${REL} $`],
  'breaking-major-version-in-place': [`changed-id ${REL}`, `changed-topic ${REL}`],
};

for (const [name, expected] of Object.entries(breaking)) {
  test(`${name} fails`, () => {
    assert.deepEqual(keys(run(name)).sort(), [...expected].sort());
  });
}

for (const name of ['compatible-optional-property-added', 'compatible-enum-value-added', 'compatible-annotations-changed']) {
  test(`${name} passes`, () => {
    assert.deepEqual(keys(run(name)), []);
  });
}

test('every fixture directory is covered by a test', () => {
  const covered = new Set([...Object.keys(breaking), 'compatible-optional-property-added', 'compatible-enum-value-added', 'compatible-annotations-changed']);
  assert.deepEqual(fs.readdirSync(FIXTURES).filter((d) => !covered.has(d)), []);
});

test('removing a schema file is breaking', () => {
  const base = fs.readFileSync(path.join(FIXTURES, 'compatible-enum-value-added', 'base.schema.json'), 'utf8');
  assert.deepEqual(keys(checkFileChange(REL, base, null)), [`removed-schema ${REL}`]);
});

test('accepted-breaking entries suppress only the listed findings', () => {
  const accepted = readAccepted(`# v2 published on evt.tst.sample.created.v2, dual-publish until all consumers moved\nremoved-property ${REL} $.note\n`);
  const findings = run('breaking-removed-property').concat(run('breaking-newly-required'));
  assert.deepEqual(keys(filterAccepted(findings, accepted).open), [`newly-required ${REL} $.note`]);
});
