# Event schema compatibility policy

Status: **Proposed** (API Governance Guild review required; not in force until the guild merges it).

Applies to every event payload schema under `schemas/`. Naming follows
[`docs/NAMING_CONVENTION_DDD_EDA_BUSINESS_CONTEXT.md`](../docs/NAMING_CONVENTION_DDD_EDA_BUSINESS_CONTEXT.md).

## 1. What a schema describes

- One file per topic: `schemas/<ctx>/<aggregate>/<event>.v<N>.schema.json` describes the `data` payload of
  topic `evt.<ctx>.<aggregate>.<event>.v<N>` (field `x-topic`).
- The envelope (`eventId`, `eventType`, `occurredAt`, `aggregateId`, `aggregateVersion`, `correlationId`,
  `causationId`, `producer`, `data`) is `schemas/common/event-envelope.v1.schema.json`. Event schemas point to
  it with `x-envelope`.
- `$id` is `https://schemas.fintechbankx.example/<ctx>/<aggregate>/<event>/v<N>`. The host is an example
  domain; it is an identifier, not a URL that is served.
- JSON Schema draft 2020-12. Each file is self-contained (shared definitions are copied into `$defs`).

## 2. Compatibility mode: FULL (backward and forward)

A change to an existing `.v<N>` file must keep two things working:

1. Consumers that move to the new schema can still read events written with the old one (replay, DLQ
   re-drive, retained topic data).
2. Events written by producers on the new schema do not break consumers that still use the old one.

The gate `scripts/ci/check-compatibility.mjs` compares every schema that exists at the merge base of
`BASE_REF` (default `origin/main`) with the working tree. It fails on:

| Rule | Example | Why it breaks |
|---|---|---|
| `removed-schema` | file deleted | consumers lose their contract |
| `changed-id`, `changed-topic` | `x-topic` edited from `.v1` to `.v2` in the `.v1` file | a new major version must be a new file |
| `removed-property` | `$.note` removed, including properties inside `$defs` or `allOf` | old consumers read a field that is no longer produced |
| `newly-required` | `note` added to `required`, or a new required property | old data does not carry it, so new consumers reject replayed events |
| `changed-type` | `string` to `["string","null"]`, or `number` to `string` | either side fails to parse; widening to null breaks old consumers |
| `no-longer-required` | `score` dropped from `required` | new producers may omit it and consumers on the old schema reject the event |
| `changed-event-type` | `x-event-type` edited in the `.v1` file | consumers route on `eventType`; a new type is a new major version |
| `changed-const` | a `const` added, removed or changed | either side rejects the other's value |
| `changed-constraint` | `pattern`, `format`, length, range or item limits added, removed or changed | tightened: replayed events fail; loosened: old consumers reject new values |
| `removed-enum-value` | `CLOSED` removed from `status` | old data still contains the value |
| `tightened-additional-properties` | `additionalProperties` absent/`true` to `false` or a schema | old data with extra fields is rejected |

Compatible (minor) changes: a new optional property, a new enum value, description, example or title
changes. Consumers must ignore unknown fields and handle unknown enum values with a default branch.

Validation keywords other than the ones above (`pattern`, `minLength`, `maximum`, ...) are not checked by
the gate. Tightening them can still reject old data; reviewers treat that as breaking.

## 3. Breaking changes: new major version

1. Add a new file `<event>.v<N+1>.schema.json` with `x-topic` `evt.<ctx>.<aggregate>.<event>.v<N+1>`. Never
   edit the `.v<N>` file into the new shape.
2. The provider publishes both topics (dual-publish, from the same outbox record) until every consumer listed
   in the provider README `consumed_events` has moved.
3. Only then may `.v<N>` be retired. Its removal is a `removed-schema` finding and needs an exception entry.

## 4. Exceptions

`compatibility/accepted-breaking.txt` lists approved findings, one key per line exactly as the gate prints it,
with a `#` comment that names the approval (ADR or backlog id) and the dual-publish plan. Accepted findings
are still printed. Add an entry only in a PR approved by the API Governance Guild.

## 5. How a provider registers a new event

1. **Provider repository:** add or change the AsyncAPI contract next to the code that publishes the event
   (transactional outbox, envelope, topic in the service namespace), in the same PR.
2. **AsyncAPI catalog** (`fintechbankx-governance-api-contracts-asyncapi-catalog`): mirror the contract in
   `asyncapi/<service-id>.yaml` and update `catalog/index.json` in a separate PR. Its gates check naming,
   namespace ownership, the envelope and breaking changes.
3. **This repository:** after the catalog PR merges, regenerate the payload schemas and open a PR:

   ```bash
   node scripts/sync/from-asyncapi.mjs <path-to-asyncapi-catalog-checkout>
   npm test
   ```

   The sync script writes only files whose `x-source` points at the AsyncAPI catalog, never deletes files,
   and warns about generated schemas whose channel disappeared. `--check` reports drift without writing.
4. **Consumers** change last, against the merged schema.

Schemas that do not come from the catalog (imported monolith contracts) carry their origin in `x-source` and are
edited by hand under the same rules. An imported contract enters the registry only once its owning context and
namespace are decided: the monolith's open-finance `payment-submitted-v1` waits for the PISP ownership decision
(alignment matrix row LP-07).

## 6. Versioning

- Topic, file name, `$id` and `eventType` share one major version. The validator
  (`scripts/ci/validate-schemas.mjs`) fails when the file version and the `x-topic` version differ.
- Minor changes do not change any name; the AsyncAPI document records them in `info.version`.
- A schema is never edited to a lower guarantee in place; history lives in git, not in extra files.
