# SecureAgent – Database Design

Status: **Implemented (Phase 2, migration `afb3ff51caae`)**. PostgreSQL 16, SQLAlchemy 2.x ORM, Alembic migrations.
All primary keys are UUIDs. All timestamps are `timestamptz` (UTC).

Fields marked **(+)** are additions beyond the brief's model list, needed for
idempotency, demo labelling or traceability. They are recorded in
`PROJECT_MEMORY.md` §14.

## ER Overview

```
users 1─* targets 1─* authorization_records
users 1─* security_audits *─1 targets
security_audits 1─1 reconnaissance_results
security_audits 1─* vulnerabilities
security_audits 1─1 security_reports
security_audits 1─* audit_logs
```

## Tables

### users
| Column | Type | Constraints |
|---|---|---|
| id | uuid | PK |
| name | varchar(120) | not null |
| email | varchar(255) | not null, unique (lower-cased), indexed |
| password_hash | varchar(255) | not null (argon2/bcrypt) |
| role | enum(`admin`,`auditor`) | not null, default `auditor` |

Enum columns are stored as `varchar(32)` + CHECK constraint (not native PG enums).
| created_at | timestamptz | not null, default now |

### targets
| Column | Type | Constraints |
|---|---|---|
| id | uuid | PK |
| user_id | uuid | FK users ON DELETE CASCADE, indexed |
| name | varchar(120) | not null |
| url | varchar(2048) | not null |
| description | text | |
| authorization_confirmed | bool | not null, default false |
| authorization_timestamp | timestamptz | null |
| status | enum(`pending`,`validated`,`rejected`,`archived`) | not null |
| scope | jsonb | `{allowed_hosts:[], path_prefixes:[]}` |
| validation_message **(+)** | text | last safety-validation result |
| created_at / updated_at | timestamptz | |

Unique: `(user_id, url)`.

### authorization_records
| Column | Type | Constraints |
|---|---|---|
| id | uuid | PK |
| target_id | uuid | FK targets CASCADE, indexed |
| user_id | uuid | FK users CASCADE |
| confirmed | bool | not null |
| statement **(+)** | text | exact confirmation text the user accepted |
| timestamp | timestamptz | not null |
| scope | jsonb | scope snapshot at authorization time |

Append-only (never updated) — it is an audit trail.

### security_audits
| Column | Type | Constraints |
|---|---|---|
| id | uuid | PK |
| target_id | uuid | FK targets CASCADE, indexed |
| user_id | uuid | FK users CASCADE, indexed |
| status | enum(`queued`,`running`,`completed`,`failed`,`stopped`) | indexed |
| current_stage | varchar(40) | |
| progress | smallint | check 0–100 |
| is_demo **(+)** | bool | not null default false |
| stage_state **(+)** | jsonb | per-stage started/completed timestamps + errors (resumability) |
| started_at / completed_at | timestamptz | |
| error_message | text | |
| created_at **(+)** | timestamptz | |

### reconnaissance_results
`id, audit_id (FK, unique), technologies jsonb, endpoints jsonb, api_endpoints jsonb,
forms jsonb, headers jsonb, raw_result jsonb (size-capped), created_at`

### vulnerabilities
| Column | Type | Notes |
|---|---|---|
| id | uuid | PK |
| audit_id | uuid | FK CASCADE, indexed |
| fingerprint **(+)** | char(64) | unique with audit_id |
| title, type | varchar | |
| endpoint | varchar(2048) | |
| parameter | varchar(255) | null |
| severity | enum(`critical`,`high`,`medium`,`low`,`informational`) | indexed |
| confidence | float | check 0–1 |
| status | enum(`confirmed`,`likely`,`suspicious`,`false_positive`,`informational`) | indexed |
| status_reason **(+)** | text | validator's explanation |
| sources **(+)** | jsonb | e.g. `["zap","nuclei"]` |
| description, impact, evidence, remediation | text | |
| validation_result | jsonb | |
| owasp_category | varchar(80) | indexed |
| cwe | varchar(20) | e.g. `CWE-79` |
| cve | varchar(40) | null → "Not applicable / no specific CVE identified." |
| cvss | jsonb | `{score, vector, version}` or null → "CVSS not determined." |
| created_at / updated_at | timestamptz | |

### security_reports
`id, audit_id (FK, unique), summary text, report_html text, report_path varchar
(PDF on disk under REPORTS_DIR), generated_at`

### audit_logs
`id, audit_id (FK, indexed), agent varchar(40), action varchar(80), status
enum(info,success,warning,error), message text, metadata jsonb, timestamp (indexed)`

Note: `metadata` is reserved in SQLAlchemy declarative classes; the ORM attribute is
named `meta` and mapped to column `metadata`.
