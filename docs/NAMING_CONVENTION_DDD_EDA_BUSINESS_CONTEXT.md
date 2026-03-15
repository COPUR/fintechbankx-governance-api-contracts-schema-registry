# Naming Convention Standard (DDD + EDA + Business Context)

## Objective

Define a single enterprise naming standard for newly created:

1. Repositories
2. Runtime services
3. Applications
4. Databases and schemas
5. Event topics and contracts

This standard is based on bounded context ownership, event-driven integration, and low-coupling design.

## Core Principles

1. Names must reflect business capability, not use-case numbers.
2. Each bounded context owns its naming namespace.
3. Event names are domain facts in past tense.
4. Versioning is explicit in APIs and events.
5. Naming must be machine-parseable for CI policy enforcement.

## Context Codes

| Context | Code |
| --- | --- |
| Open Finance | `of` |
| Lending | `ln` |
| Payments | `pay` |
| Customer | `cus` |
| Risk | `rsk` |
| Compliance | `cmp` |
| Identity Platform | `idn` |
| Mesh Security Platform | `msh` |
| Event Platform | `evt` |
| Observability Platform | `obs` |
| Delivery Platform | `dly` |
| Infrastructure as Code Platform | `iac` |
| Contract Governance | `ctr` |
| Architecture Governance | `gov` |

## Repository Naming

Format:

`<domain-or-platform>-<capability>-service`

or for non-runtime repos:

`platform-<capability>`
`contracts-<capability>`
`governance-<capability>`

Rules:

1. Lowercase kebab-case only.
2. Singular capability names where possible.
3. No abbreviations except approved context codes in technical IDs.

Examples:

1. `fintechbankx-openfinance-consent-authorization-service`
2. `fintechbankx-payments-initiation-settlement-service`
3. `fintechbankx-platform-identity-keycloak-ldap`
4. `fintechbankx-contracts-openapi-catalog`

## Application Naming

### Spring application name

Format:

`app.<context-code>.<capability>`

Examples:

1. `app.of.consent-authorization`
2. `app.pay.initiation-settlement`
3. `app.ln.loan-lifecycle`

### Kubernetes app label

Format:

`app-<context-code>-<capability>`

Examples:

1. `app-of-consent-authorization`
2. `app-cus-profile-kyc`

### Runtime service ID

Format:

`svc-<context-code>-<capability>`

Examples:

1. `svc-of-payee-verification`
2. `svc-rsk-decisioning`

## Database and Schema Naming

### Logical database name

Format:

`db_<context-code>_<capability>_<env>`

Examples:

1. `db_of_consent_authorization_dev`
2. `db_pay_initiation_settlement_staging`
3. `db_ln_loan_lifecycle_prod`

### Schema name

Format:

`sc_<context-code>_<capability>`

Examples:

1. `sc_of_personal_financial_data`
2. `sc_cus_profile_kyc`

### Table naming

Format:

`<aggregate>_<entity>`

Examples:

1. `consent_record`
2. `payment_instruction`
3. `loan_schedule_item`

## API Naming

### External API path

Format:

`/api/<bounded-context>/v<major>/...`

Example:

`/api/open-finance/v1/consents`

### Operation IDs

Format:

`<verb><AggregateOrCapability>`

Examples:

1. `createConsent`
2. `listCorporateAccounts`
3. `verifyPayee`

## Event-Driven Naming (Kafka / AsyncAPI)

### Topic naming

Format:

`evt.<context-code>.<aggregate>.<event-name>.v<major>`

Examples:

1. `evt.of.consent.created.v1`
2. `evt.pay.payment.settled.v1`
3. `evt.ln.loan.disbursed.v1`

### Event type (header/payload metadata)

Format:

`<Context>.<Aggregate>.<PastTenseEvent>.v<major>`

Examples:

1. `OpenFinance.Consent.Created.v1`
2. `Payments.Payment.Failed.v1`

### Consumer group naming

Format:

`cg.<service-id>.<purpose>.v<major>`

Example:

`cg.svc-cmp-evidence.payment-compliance-check.v1`

### Dead-letter topics

Format:

`evt.<context-code>.<aggregate>.dlq.v<major>`

Example:

`evt.pay.payment.dlq.v1`

## Branch and Release Naming for New Repositories

Default branches:

1. `main`
2. `dev`
3. `staging`

Release branches:

1. `release/<yyyy-mm>-<stream>`
2. `hotfix/<ticket-or-incident-id>`

## Ownership Tags

Every repository must include these metadata tags in `README` and `CODEOWNERS`:

1. `bounded_context`
2. `owning_squad`
3. `upstream_dependencies`
4. `published_events`
5. `consumed_events`
6. `data_owner`

## Compliance Enforcement Hooks

The following CI checks should enforce this standard:

1. Repository name lint
2. Spring application name lint
3. OpenAPI operation and version lint
4. AsyncAPI topic naming lint
5. Database/schema naming lint for Flyway/Liquibase migrations
