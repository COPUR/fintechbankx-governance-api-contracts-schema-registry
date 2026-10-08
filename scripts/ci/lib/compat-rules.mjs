// Backward-compatibility rules for event payload schemas.
// Status: Proposed (API Governance Guild review required). Policy: compatibility/POLICY.md.
//
// A change to an existing schema file must keep both directions working:
//   - consumers on the new schema can read data written with the old schema, and
//   - data written by new producers does not break consumers still on the old schema.
// Practical rules (each finding key is "<rule> <file> [<path>] [<value>]"):
//   removed-schema                  the file was deleted
//   changed-id / changed-topic      $id or x-topic changed in place (a new major version is a new .v<N+1> file)
//   removed-property                a property path is gone (properties inside $ref/$defs and allOf included)
//   newly-required                  a property became required, or a new property is required
//   changed-type                    the declared JSON type(s) of a path changed (widening included)
//   removed-enum-value              an enum value is gone
//   tightened-additional-properties additionalProperties went from absent/true to false or a schema,
//                                   or from a schema to false
// Annotations (description, examples, title, x-*) and validation keywords not listed above are not checked.

const resolveLocal = (root, ref) => {
  if (!ref.startsWith('#')) throw new Error(`only local $refs are supported in registry schemas: ${ref}`);
  let node = root;
  for (const part of ref.replace(/^#\/?/, '').split('/').filter(Boolean)) {
    const key = decodeURIComponent(part).replace(/~1/g, '/').replace(/~0/g, '~');
    if (node === null || typeof node !== 'object' || !(key in node)) throw new Error(`cannot resolve ${ref}`);
    node = node[key];
  }
  return node;
};

const apNorm = (v) => {
  if (v === undefined || v === true) return 'open';
  if (v === false) return 'closed';
  return `schema:${JSON.stringify(v)}`;
};

/** Merged view of a list of schemas (allOf semantics, local $refs followed). */
function view(root, schemas) {
  const v = { types: new Set(), props: new Map(), required: new Set(), items: [], enum: null, ap: undefined };
  const visit = (s, depth) => {
    if (depth > 40 || s === null || typeof s !== 'object') return;
    if (typeof s.$ref === 'string') visit(resolveLocal(root, s.$ref), depth + 1);
    if (s.type !== undefined) (Array.isArray(s.type) ? s.type : [s.type]).forEach((t) => v.types.add(t));
    if (Array.isArray(s.enum)) v.enum = [...(v.enum ?? []), ...s.enum];
    if (s.additionalProperties !== undefined) v.ap = s.additionalProperties;
    if (Array.isArray(s.required)) s.required.forEach((r) => v.required.add(r));
    for (const [name, sub] of Object.entries(s.properties ?? {})) {
      if (!v.props.has(name)) v.props.set(name, []);
      v.props.get(name).push(sub);
    }
    if (s.items && typeof s.items === 'object') v.items.push(s.items);
    (s.allOf ?? []).forEach((p) => visit(p, depth + 1));
  };
  schemas.forEach((s) => visit(s, 0));
  return v;
}

/** Map<path, { types, required, enum, ap, isObject }>; root '$', properties '$.a.b', array items '[]'. */
export function flattenSchema(schema) {
  const out = new Map();
  const walk = (schemas, p, required, depth) => {
    if (depth > 40) return;
    const v = view(schema, schemas);
    out.set(p, {
      types: [...v.types].sort().join('|') || null,
      required,
      enum: v.enum ? [...new Set(v.enum.map((x) => JSON.stringify(x)))].sort() : null,
      ap: apNorm(v.ap),
      isObject: v.types.has('object') || v.props.size > 0,
    });
    for (const [name, subs] of v.props) walk(subs, `${p}.${name}`, v.required.has(name), depth + 1);
    if (v.items.length > 0) walk(v.items, `${p}[]`, true, depth + 1);
  };
  walk([schema], '$', true, 0);
  return out;
}

export function compareSchemas(rel, base, head) {
  const findings = [];
  const add = (rule, subject, detail) => findings.push({ rule, key: `${rule} ${rel}${subject ? ` ${subject}` : ''}`, detail });
  if (base.$id !== head.$id) add('changed-id', '', `$id changed from ${base.$id} to ${head.$id}; publish a new major version as a new file`);
  if (base['x-topic'] !== head['x-topic']) add('changed-topic', '', `x-topic changed from ${base['x-topic']} to ${head['x-topic']}; publish a new major version as a new file`);
  const b = flattenSchema(base);
  const h = flattenSchema(head);
  for (const [p, bi] of b) {
    const hi = h.get(p);
    if (!hi) {
      add('removed-property', p, `${p} was removed`);
      continue;
    }
    if (hi.required && !bi.required) add('newly-required', p, `${p} is now required`);
    if (bi.types && hi.types && bi.types !== hi.types) add('changed-type', p, `type changed from ${bi.types} to ${hi.types}`);
    if (bi.types && !hi.types) add('changed-type', p, `type constraint ${bi.types} was removed`);
    if (!bi.types && hi.types) add('changed-type', p, `type constraint ${hi.types} was added`);
    if (bi.enum && hi.enum) {
      bi.enum.filter((x) => !hi.enum.includes(x)).forEach((x) => add('removed-enum-value', `${p} ${x}`, `enum value ${x} was removed from ${p}`));
    }
    if (bi.isObject && ((bi.ap === 'open' && hi.ap !== 'open') || (bi.ap.startsWith('schema:') && hi.ap === 'closed'))) {
      add('tightened-additional-properties', p, `additionalProperties tightened from ${bi.ap} to ${hi.ap.startsWith('schema:') ? 'a schema' : hi.ap}`);
    }
  }
  for (const [p, hi] of h) {
    if (b.has(p) || !hi.required || p === '$') continue;
    const parent = p.replace(/(\.[^.[\]]+|\[\])$/, '');
    // A required child of a new optional object is not a break; a new required property of an existing object is.
    if (b.has(parent)) add('newly-required', p, `new property ${p} is required`);
  }
  return findings;
}

/** baseText null = new file (no findings); headText null = deleted file. */
export function checkFileChange(rel, baseText, headText) {
  if (baseText === null || baseText === undefined) return [];
  if (headText === null || headText === undefined) {
    return [{ rule: 'removed-schema', key: `removed-schema ${rel}`, detail: `${rel} was deleted` }];
  }
  return compareSchemas(rel, JSON.parse(baseText), JSON.parse(headText));
}

export function readAccepted(text) {
  return new Set((text ?? '').split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean));
}

export function filterAccepted(findings, accepted) {
  return {
    open: findings.filter((f) => !accepted.has(f.key)),
    accepted: findings.filter((f) => accepted.has(f.key)),
  };
}
