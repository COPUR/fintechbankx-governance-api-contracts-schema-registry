#!/usr/bin/env node
// Generates event payload JSON Schemas (draft 2020-12) from the AsyncAPI catalog.
// Status: Proposed (API Governance Guild review required).
//
// Usage:
//   node scripts/sync/from-asyncapi.mjs <path-to-asyncapi-catalog-checkout> [--check]
//
// For every top-level asyncapi/*.yaml in the catalog checkout, every aggregate channel
// evt.<ctx>.<aggregate>.v<M> (one topic per aggregate, ADR-019) and every message on it, the `data` schema
// of the message is written to
//   schemas/<ctx>/<aggregate>/<event>.v<N>.schema.json
// where <event> is the kebab-case event name and N the major of the message's eventType
// <Context>.<Aggregate>.<Event>.v<N>. Dead-letter channels are skipped.
// and the shared envelope to schemas/common/event-envelope.v1.schema.json.
// Every $ref (local components or the common envelope file) is inlined into $defs so each schema is
// self-contained. Files whose x-source does not come from the AsyncAPI catalog (imported schemas) are
// never touched. --check writes nothing and exits 1 when a generated file would change.
import fs from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';

export const ID_BASE = 'https://schemas.fintechbankx.example';
export const CATALOG_REPO = 'fintechbankx-governance-api-contracts-asyncapi-catalog';
const TOPIC_RE = /^evt\.([a-z]+)\.([a-z0-9-]+)\.v([0-9]+)$/;
const DLQ_RE = /^evt\.[a-z]+\.[a-z0-9-]+\.dlq\.v[0-9]+$/;
const EVENT_TYPE_RE = /^[A-Z][A-Za-z]*\.[A-Z][A-Za-z]*\.([A-Z][A-Za-z0-9]*)\.v([0-9]+)$/;
const kebab = (name) => name.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();

function pointerGet(doc, pointer, where) {
  let node = doc;
  for (const part of pointer.replace(/^#\/?/, '').split('/').filter(Boolean)) {
    const key = decodeURIComponent(part).replace(/~1/g, '/').replace(/~0/g, '~');
    if (node === null || typeof node !== 'object' || !(key in node)) throw new Error(`${where}: cannot resolve ${pointer}`);
    node = node[key];
  }
  return node;
}

/** Loads YAML documents relative to the catalog root, cached. */
function makeLoader(root) {
  const cache = new Map();
  return (rel) => {
    if (!cache.has(rel)) cache.set(rel, parse(fs.readFileSync(path.join(root, rel), 'utf8')));
    return cache.get(rel);
  };
}

/** Splits a $ref into { file, pointer } relative to the catalog root. */
function refTarget(ref, fromFile) {
  const i = ref.indexOf('#');
  const filePart = i === -1 ? ref : ref.slice(0, i);
  const pointer = i === -1 ? '#' : ref.slice(i);
  const file = filePart === '' ? fromFile : path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), filePart));
  return { file, pointer };
}

/**
 * Deep-copies a schema, inlining every $ref target into defs and rewriting the ref to #/$defs/<Name>.
 * defs: Map<name, { key, schema }> shared across one output document.
 */
function inline(node, fromFile, load, defs) {
  if (Array.isArray(node)) return node.map((n) => inline(n, fromFile, load, defs));
  if (node === null || typeof node !== 'object') return node;
  if (typeof node.$ref === 'string') {
    let { file, pointer } = refTarget(node.$ref, fromFile);
    // Follow pure aliases (a target that is only { $ref }) so one definition gets one name.
    for (let i = 0; i < 20; i++) {
      const target = pointerGet(load(file), pointer, file);
      if (!target || typeof target !== 'object' || Object.keys(target).length !== 1 || typeof target.$ref !== 'string') break;
      ({ file, pointer } = refTarget(target.$ref, file));
    }
    const key = `${file}${pointer}`;
    const baseName = pointer.split('/').pop();
    let name = baseName;
    for (let n = 2; defs.has(name) && defs.get(name).key !== key; n++) name = `${baseName}${n}`;
    if (!defs.has(name)) {
      defs.set(name, { key, schema: null });
      defs.get(name).schema = inline(pointerGet(load(file), pointer, file), file, load, defs);
    }
    const rest = Object.fromEntries(Object.entries(node).filter(([k]) => k !== '$ref'));
    return { $ref: `#/$defs/${name}`, ...inline(rest, fromFile, load, defs) };
  }
  return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, k === 'properties' ? Object.fromEntries(Object.entries(v).map(([pk, pv]) => [pk, inline(pv, fromFile, load, defs)])) : inline(v, fromFile, load, defs)]));
}

const withDefs = (schema, defs) => {
  if (defs.size === 0) return schema;
  const sorted = [...defs.entries()].sort(([a], [b]) => a.localeCompare(b));
  return { ...schema, $defs: Object.fromEntries(sorted.map(([n, d]) => [n, d.schema])) };
};

const deref = (node, file, load) => {
  let cur = node;
  let curFile = file;
  for (let i = 0; i < 20 && cur && typeof cur.$ref === 'string'; i++) {
    const t = refTarget(cur.$ref, curFile);
    cur = pointerGet(load(t.file), t.pointer, t.file);
    curFile = t.file;
  }
  return { node: cur, file: curFile };
};

export function buildEnvelope(load) {
  const file = 'asyncapi/common/event-envelope.yaml';
  const doc = load(file);
  const defs = new Map();
  const envelope = inline(doc.EventEnvelope, file, load, defs);
  for (const name of Object.keys(doc).filter((k) => k !== 'EventEnvelope').sort()) {
    if (!defs.has(name)) defs.set(name, { key: `${file}#/${name}`, schema: inline(doc[name], file, load, defs) });
  }
  return withDefs({
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: `${ID_BASE}/common/event-envelope/v1`,
    title: 'FinTechBankX event envelope v1',
    'x-status': 'Proposed',
    'x-source': `${CATALOG_REPO} ${file}#/EventEnvelope`,
    ...envelope,
  }, defs);
}

/** True when every operation on the channel receives (a topic this service consumes, not one it owns). */
function receivesOnly(doc, chKey) {
  const ops = Object.values(doc.operations ?? {}).filter((op) => op?.channel?.$ref === `#/channels/${chKey}`);
  return ops.length > 0 && ops.every((op) => op.action === 'receive');
}

/** Returns [{ relPath, schema }] for every event payload in the catalog checkout. */
export function buildFromCatalog(root) {
  const load = makeLoader(root);
  const out = [{ relPath: 'schemas/common/event-envelope.v1.schema.json', schema: buildEnvelope(load) }];
  const specs = fs.readdirSync(path.join(root, 'asyncapi')).filter((f) => /\.ya?ml$/.test(f)).sort();
  for (const name of specs) {
    const file = `asyncapi/${name}`;
    const doc = load(file);
    const producer = doc?.info?.['x-service-id'];
    for (const [chKey, channel] of Object.entries(doc.channels ?? {})) {
      if (DLQ_RE.test(channel.address ?? '')) continue; // dead-letter topics carry the original record
      const m = TOPIC_RE.exec(channel.address ?? '');
      if (!m) throw new Error(`${file} channels.${chKey}: address ${channel.address} is not the aggregate topic evt.<ctx>.<aggregate>.v<M>`);
      const [, ctx, aggregate] = m;
      if (receivesOnly(doc, chKey)) continue; // consumed topics are generated from the provider's spec
      const messages = Object.entries(channel.messages ?? {});
      if (messages.length === 0) throw new Error(`${file} channels.${chKey}: no messages`);
      for (const [msgKey, msgRef] of messages) {
        const where = `${file} channels.${chKey}.messages.${msgKey}`;
        const { node: message, file: mFile } = deref(msgRef, file, load);
        const parts = message?.payload?.allOf ?? [];
        const part = parts.find((p) => p?.properties?.data);
        if (!part) throw new Error(`${where}: message payload has no allOf part with properties.data`);
        const eventType = part.properties.eventType?.const;
        const e = EVENT_TYPE_RE.exec(eventType ?? '');
        if (!e) throw new Error(`${where}: payload eventType const ${eventType} is not <Context>.<Aggregate>.<Event>.v<N>`);
        const [, eventName, version] = e;
        const event = kebab(eventName);
        const dataRef = part.properties.data;
        const { node: data } = deref(dataRef, mFile, load);
        const defs = new Map();
        const body = inline(data, mFile, load, defs);
        const sourceName = typeof dataRef.$ref === 'string' ? dataRef.$ref.split('/').pop() : `${chKey}.${msgKey}.data`;
        const schema = withDefs({
          $schema: 'https://json-schema.org/draft/2020-12/schema',
          $id: `${ID_BASE}/${ctx}/${aggregate}/${event}/v${version}`,
          title: `${eventType} data`,
          'x-status': 'Proposed',
          'x-topic': channel.address,
          'x-event-type': eventType,
          'x-producer': part.properties.producer?.const ?? producer,
          'x-envelope': `${ID_BASE}/common/event-envelope/v1`,
          'x-source': `${CATALOG_REPO} ${file}#/components/schemas/${sourceName}`,
          ...body,
        }, defs);
        out.push({ relPath: `schemas/${ctx}/${aggregate}/${event}.v${version}.schema.json`, schema });
      }
    }
  }
  return out;
}

const serialize = (schema) => `${JSON.stringify(schema, null, 2)}\n`;

function main() {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const root = args.find((a) => !a.startsWith('--'));
  if (!root || !fs.existsSync(path.join(root, 'asyncapi'))) {
    console.error('usage: node scripts/sync/from-asyncapi.mjs <path-to-asyncapi-catalog-checkout> [--check]');
    process.exit(2);
  }
  const generated = buildFromCatalog(root);
  let drift = 0;
  for (const { relPath, schema } of generated) {
    const text = serialize(schema);
    const current = fs.existsSync(relPath) ? fs.readFileSync(relPath, 'utf8') : null;
    if (current !== null && !JSON.parse(current)['x-source']?.startsWith(CATALOG_REPO)) {
      console.error(`skip ${relPath}: exists and is not generated from the AsyncAPI catalog`);
      continue;
    }
    if (current === text) {
      console.log(`same    ${relPath}`);
      continue;
    }
    drift++;
    if (check) {
      console.error(`drift   ${relPath}`);
    } else {
      fs.mkdirSync(path.dirname(relPath), { recursive: true });
      fs.writeFileSync(relPath, text);
      console.log(`${current === null ? 'created' : 'updated'} ${relPath}`);
    }
  }
  // Report generated files that no longer have a source channel (never deleted automatically).
  const wanted = new Set(generated.map((g) => g.relPath));
  const walk = (d) => (fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)])) : []);
  for (const f of walk('schemas').filter((x) => x.endsWith('.schema.json')).map((x) => x.split(path.sep).join('/'))) {
    const src = JSON.parse(fs.readFileSync(f, 'utf8'))['x-source'] ?? '';
    if (src.startsWith(CATALOG_REPO) && !wanted.has(f)) console.warn(`stale   ${f}: no longer in the AsyncAPI catalog (removal is a breaking change)`);
  }
  console.log(`${generated.length} schema(s) from the AsyncAPI catalog, ${drift} ${check ? 'out of date' : 'written'}`);
  if (check && drift > 0) process.exit(1);
}

main();
