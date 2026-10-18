#!/usr/bin/env node
// Event schema layout and compile gate.
// Status: Proposed (API Governance Guild review required).
//
// Usage: node scripts/ci/validate-schemas.mjs [repoRoot]
//
// Fails (exit 1) when a file under schemas/:
//   - is not at schemas/<ctx>/<aggregate>/<event>.v<N>.schema.json or schemas/common/<name>.v<N>.schema.json;
//   - is not valid JSON, does not declare draft 2020-12, or does not compile with Ajv 2020 (strict mode);
//   - has a $id other than https://schemas.fintechbankx.example/<ctx>/<aggregate>/<event>/v<N>
//     (common: https://schemas.fintechbankx.example/common/<name>/v<N>);
//   - has no title;
//   - (event schemas) has no x-topic, or x-topic is not the aggregate topic evt.<ctx>.<aggregate>.v<M> for the
//     path's ctx and aggregate (one topic per aggregate, ADR-019; the topic major M is independent of the file);
//   - (event schemas) has no x-event-type, or its major differs from the file version (file version == event
//     major: a breaking change is a new file and a new event major on the same topic);
//   - shares its $id or x-event-type with another file.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

export const ID_BASE = 'https://schemas.fintechbankx.example';
const EVENT_PATH_RE = /^schemas\/([a-z]+)\/([a-z0-9-]+)\/([a-z0-9-]+)\.v([0-9]+)\.schema\.json$/;
const COMMON_PATH_RE = /^schemas\/common\/([a-z0-9-]+)\.v([0-9]+)\.schema\.json$/;
const TOPIC_RE = /^evt\.([a-z]+)\.([a-z0-9-]+)\.v([0-9]+)$/;
const EVENT_TYPE_RE = /^[A-Z][A-Za-z]*\.[A-Z][A-Za-z]*\.[A-Z][A-Za-z]*\.v([0-9]+)$/;

export function listSchemaFiles(root) {
  const base = path.join(root, 'schemas');
  const walk = (d) => (fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)])) : []);
  return walk(base).map((f) => path.relative(root, f).split(path.sep).join('/')).sort();
}

const collectExtensionKeywords = (node, out = new Set()) => {
  if (Array.isArray(node)) node.forEach((n) => collectExtensionKeywords(n, out));
  else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      if (k.startsWith('x-')) out.add(k);
      collectExtensionKeywords(v, out);
    }
  }
  return out;
};

export function newAjv() {
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  // OpenAPI/AsyncAPI integer formats used by the catalog; annotation only.
  ajv.addFormat('int32', { type: 'number', validate: (n) => Number.isInteger(n) && n >= -(2 ** 31) && n < 2 ** 31 });
  ajv.addFormat('int64', { type: 'number', validate: (n) => Number.isInteger(n) });
  return ajv;
}

/** Expected $id and topic for a repo-relative path, or { error }. */
export function expectedFor(rel) {
  let m = COMMON_PATH_RE.exec(rel);
  if (m) return { kind: 'common', id: `${ID_BASE}/common/${m[1]}/v${m[2]}` };
  m = EVENT_PATH_RE.exec(rel);
  if (m && m[1] !== 'common') {
    const [, ctx, aggregate, event, version] = m;
    return { kind: 'event', id: `${ID_BASE}/${ctx}/${aggregate}/${event}/v${version}`, topicPrefix: `evt.${ctx}.${aggregate}`, version };
  }
  return { error: `${rel}: path must be schemas/<ctx>/<aggregate>/<event>.v<N>.schema.json or schemas/common/<name>.v<N>.schema.json` };
}

export function validateSchemas(root) {
  const errors = [];
  const notes = [];
  const files = listSchemaFiles(root);
  const seenId = new Map();
  const seenTopic = new Map();
  const parsed = [];
  for (const rel of files) {
    const exp = expectedFor(rel);
    if (exp.error) {
      errors.push(exp.error);
      continue;
    }
    let schema;
    try {
      schema = JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'));
    } catch (e) {
      errors.push(`${rel}: invalid JSON: ${e.message}`);
      continue;
    }
    if (schema.$schema !== 'https://json-schema.org/draft/2020-12/schema') errors.push(`${rel}: $schema must be https://json-schema.org/draft/2020-12/schema`);
    if (schema.$id !== exp.id) errors.push(`${rel}: $id ${schema.$id} must be ${exp.id}`);
    if (typeof schema.title !== 'string' || schema.title.trim() === '') errors.push(`${rel}: title is required`);
    if (exp.kind === 'event') {
      const topic = schema['x-topic'];
      const t = TOPIC_RE.exec(topic ?? '');
      if (!t) {
        errors.push(`${rel}: x-topic ${topic} must be the aggregate topic evt.<ctx>.<aggregate>.v<M> (one topic per aggregate, ADR-019)`);
      } else if (!topic.startsWith(`${exp.topicPrefix}.v`)) {
        errors.push(`${rel}: x-topic ${topic} must be ${exp.topicPrefix}.v<M> (path and topic must agree)`);
      }
      const eventType = schema['x-event-type'];
      const e = EVENT_TYPE_RE.exec(eventType ?? '');
      if (!e) {
        errors.push(`${rel}: x-event-type ${eventType} must match <Context>.<Aggregate>.<PastTenseEvent>.v<N>`);
      } else {
        if (e[1] !== exp.version) errors.push(`${rel}: file version v${exp.version} does not match the x-event-type major v${e[1]} (a new event major is a new file)`);
        if (seenTopic.has(eventType)) errors.push(`${rel}: x-event-type ${eventType} also used by ${seenTopic.get(eventType)}`);
        else seenTopic.set(eventType, rel);
      }
    }
    if (schema.$id) {
      if (seenId.has(schema.$id)) errors.push(`${rel}: $id ${schema.$id} also used by ${seenId.get(schema.$id)}`);
      else seenId.set(schema.$id, rel);
    }
    parsed.push({ rel, schema });
  }
  // Compile: register all schemas first so cross-file $id references resolve, then compile each.
  const ajv = newAjv();
  const keywords = new Set();
  parsed.forEach(({ schema }) => collectExtensionKeywords(schema, keywords));
  keywords.forEach((k) => ajv.addKeyword(k)); // annotation-only extension keywords (x-topic, x-source, ...)
  const registered = [];
  for (const p of parsed) {
    try {
      ajv.addSchema(p.schema);
      registered.push(p);
    } catch (e) {
      errors.push(`${p.rel}: cannot register schema: ${e.message}`);
    }
  }
  for (const { rel, schema } of registered) {
    try {
      ajv.getSchema(schema.$id) ?? ajv.compile(schema);
      notes.push(`${rel}: compiled${schema['x-topic'] ? ` (${schema['x-topic']})` : ''}`);
    } catch (e) {
      errors.push(`${rel}: does not compile: ${e.message}`);
    }
  }
  return { errors, notes, count: files.length };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const root = path.resolve(process.argv[2] ?? '.');
  const { errors, notes, count } = validateSchemas(root);
  notes.forEach((n) => console.log(`ok  ${n}`));
  if (errors.length > 0) {
    errors.forEach((e) => console.error(`ERR ${e}`));
    console.error(`schema validation failed: ${errors.length} error(s) in ${count} file(s)`);
    process.exit(1);
  }
  console.log(`schema validation passed: ${count} file(s)`);
}
