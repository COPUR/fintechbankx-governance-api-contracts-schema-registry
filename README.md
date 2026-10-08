# fintechbankx-governance-api-contracts-schema-registry

Bu repository, FinTechBankX DDD/EDA dönüşümünde **svc-ctr-schema-registry** servis yetkinliğinin kaynak kodunu, kontratlarını ve operasyonel guardrail'lerini içerir.

## Sorumluluk ve Sahiplik
| Alan | Değer |
|---|---|
| Organizasyon Modeli | Spotify Model (Tribe/Squad) |
| Tribe | Architecture & Governance Tribe |
| Squad | API Governance Guild |
| Repo Kümesi (Capability) | contracts |
| Service ID | svc-ctr-schema-registry |
| Bounded Context | schema_registry |
| Wave | 4 |
| Mimari Yaklaşım | DDD + Hexagonal + Event-Driven |

## Sorumluluk Sınırları
- Bu repo kendi bounded context domain modelinin tek yetkili sahibidir.
- Domain kuralları altyapıdan bağımsız tutulur; entegrasyonlar port/adapter katmanında yönetilir.
- API/Event kontratları geriye dönük uyumluluk kontrolleri ile korunur.
- Güvenlik guardrail'leri (mTLS, token doğrulama, idempotency, log hijyeni) CI/CD ile zorlanır.

## Kapsam
### In Scope
- schema_registry bağlamına ait uygulama kodu, testler ve otomasyon.
- Bu servise ait OpenAPI/AsyncAPI veya şema artefaktları.
- Bu servisin çalışma zamanı operasyonları (gözlemlenebilirlik, release, rollback).

### Out of Scope
- Diğer bounded context'lerin iş kuralları ve veri sahipliği.
- Paylaşımlı DB anti-pattern'i; cross-context doğrudan tablo erişimi.
- Platform dışı gizli bilgi/anahtar yönetimi (merkezi policy dışında local hardcode).

## Mühendislik Standartları
- **TDD öncelikli** geliştirme, birim test + entegrasyon testi.
- **Clean Architecture**: Domain katmanı framework bağımsız.
- **12-Factor** ve environment-driven configuration.
- **FAPI odaklı güvenlik** (OIDC/OAuth2, mTLS, DPoP gereksinimleri ilgili servislerde).
- **PII güvenliği**: loglarda maskeleme, secret'ların source/env içine yazılmaması.

## Branching ve Release Akışı
- Uzun ömürlü branch'ler: `main`, `dev`, `staging`, `local`.
- Feature branch kuralı: `codex/<kisa-aciklama>`.
- Release yaklaşımı: PR + required status checks + tag tabanlı sürümleme.

## Dokümantasyon ve Referanslar
- [Enterprise Architecture Hub](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture)
- [Secure Microservices Architecture](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/architecture/overview/SECURE_MICROSERVICES_ARCHITECTURE.md)
- [Service Data Ownership Matrix](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/SERVICE_DATA_OWNERSHIP_MATRIX.md)
- [Service API Contracts Index](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/SERVICE_API_CONTRACTS_INDEX.md)
- [Transformation Plan](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/MICROSERVICES_TRANSFORMATION_PLAN.md)
- [Capability Map (PUML)](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/puml/service-mesh/enterprise-capability-map.puml)
- [Bu Repo Dokümantasyonu](./docs)
- [Event Schema Compatibility Policy](./compatibility/POLICY.md)

## Event schemas

Status: **Proposed** (API Governance Guild review required).

| Path | Content |
|---|---|
| `schemas/<ctx>/<aggregate>/<event>.v<N>.schema.json` | `data` payload of topic `evt.<ctx>.<aggregate>.<event>.v<N>` (JSON Schema draft 2020-12, `x-topic`, `$id` `https://schemas.fintechbankx.example/<ctx>/<aggregate>/<event>/v<N>`) |
| `schemas/common/event-envelope.v1.schema.json` | Standard event envelope shared by every topic |
| `schemas/of/payment/submitted.v1.schema.json` | Imported from the source monorepo contract `contracts/events/open-finance/payment-submitted-v1.schema.json` (legacy topic `openfinance.provider.payment.v1`; owning service not assigned yet) |
| [`compatibility/POLICY.md`](compatibility/POLICY.md) | Compatibility mode, breaking-change rules, exceptions, provider registration flow, versioning |
| `compatibility/accepted-breaking.txt` | Approved exceptions to the compatibility gate |
| `scripts/sync/from-asyncapi.mjs` | Regenerates the payload schemas from the AsyncAPI catalog |

Today the schemas cover `evt.ln.loan`, `evt.pay.payment`, `evt.pay.rtp` and `evt.cus.customer` (26 generated
from `fintechbankx-governance-api-contracts-asyncapi-catalog`) plus the imported open-finance payment fact.

### Compatibility mode

BACKWARD, applied in both directions in practice: consumers on a new schema must read old events, and events
from new producers must not break consumers on the old schema. A change to an existing `.v<N>` file fails the
gate when it removes a property or schema, makes a property required, changes a type, removes an enum value,
tightens `additionalProperties`, or edits `$id` / `x-topic`. A breaking change is a new file `.v<N+1>` on a new
topic with dual-publish. Details: [`compatibility/POLICY.md`](compatibility/POLICY.md).

### Registering a new event

1. Provider repository: AsyncAPI contract and outbox publisher in the same PR.
2. AsyncAPI catalog: mirror the contract in `asyncapi/<service-id>.yaml` and `catalog/index.json`.
3. This repository: `node scripts/sync/from-asyncapi.mjs <path-to-asyncapi-catalog-checkout>`, then `npm test`, then PR.
4. Consumers change last.

### Checks

Run with Node 22 (`ci/test` runs the same through `npm ci && npm test`, with full history):

```bash
npm ci
npm test   # validate-schemas + check-compatibility (BASE_REF, default origin/main) + unit tests
```

| Script | Fails when |
|---|---|
| `scripts/ci/validate-schemas.mjs` | a file is outside the layout; invalid JSON; not draft 2020-12; does not compile (Ajv 2020 strict + ajv-formats); `$id` does not match the path; no `title`; `x-topic` missing, malformed, or not the same ctx/aggregate/event/version as the path; duplicate `$id` or `x-topic` |
| `scripts/ci/check-compatibility.mjs` | a schema that exists at the merge base of `BASE_REF` changed incompatibly (rules above) and the finding is not in `compatibility/accepted-breaking.txt` |
| `scripts/ci/test/*.test.mjs` | a compatibility rule stops failing on its fixture pair, or a compatible fixture starts failing |

### Legacy SQL reference copies

`database/*.sql` were seeded from the monorepo `security/database` directory (see `MIGRATION_GRANULARITY.md`).
They are **legacy reference copies only**: this repository does not own, run or version any database. Each
service owns its schema and migrations in its own repository (`db_<ctx>_<capability>_<env>`). The files are
kept unchanged for traceability and are not checked by the gates above.

## Güvenlik ve Uyumluluk Notları
- Gerçek secret değerleri repo veya `.env` içinde tutulmaz.
- Secret üretim/rotasyon olayları merkezi log/SIEM'e taşınır.
- CI pipeline, anonimlik ve local-path sızıntısı kontrollerini bloklayıcı olarak çalıştırır.

## Katkı
- Katkı süreci için `CONTRIBUTING.md` ve squad runbook'ları izlenmelidir.
- PR'larda mimari kararlar ADR veya backlog referansı ile ilişkilendirilmelidir.

## Cell-Based Architecture

This repository participates in the FinTechBankX cell-based resilience program.

- Plan: \
- Backlog: \

<!-- cell-architecture-start -->
## Cell-Based Architecture

This repository participates in the FinTechBankX cell-based resilience program.

- Plan: docs/architecture/CELL_BASED_ARCHITECTURE_IMPLEMENTATION_PLAN.md
- Backlog: docs/project-management/CELL_ARCHITECTURE_BACKLOG_BOARD.md
<!-- cell-architecture-end -->
