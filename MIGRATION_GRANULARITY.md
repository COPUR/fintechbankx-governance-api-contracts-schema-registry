# Migration Granularity Notes

- Repository: `fintechbankx-contracts-schema-registry`
- Source monorepo: `enterprise-loan-management-system`
- Sync date: `2026-03-15`
- Sync branch: `chore/granular-source-sync-20260313`

## Applied Rules

- dir: `security/database` -> `database`
- file: `docs/architecture/open-finance/capabilities/test-suites/requirement-traceability-matrix.md` -> `docs/requirement-traceability-matrix.md`
- file: `docs/enterprisearchitecture/implementation-development/transformation/workspace-ddd-eda-2026-03-13/NAMING_CONVENTION_DDD_EDA_BUSINESS_CONTEXT.md` -> `docs/NAMING_CONVENTION_DDD_EDA_BUSINESS_CONTEXT.md`

## Notes

- This is an extraction seed for bounded-context split migration.
- Follow-up refactoring may be needed to remove residual cross-context coupling.
- Build artifacts and local machine files are excluded by policy.

