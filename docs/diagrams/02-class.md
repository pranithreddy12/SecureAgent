# 2. Class Diagram

The implemented static-analysis domain (`backend/app/analysis/`) and how findings
flow into the shared report model. Fields are abbreviated.

```mermaid
classDiagram
    class ScanResult {
        +str root
        +list~SecretFinding~ secret_findings
        +list~Route~ routes
        +list~RouteFinding~ route_findings
        +list~SinkFinding~ sink_findings
        +list~TaintFinding~ taint_findings
        +list~IdorFinding~ idor_findings
        +list~MisconfigFinding~ misconfig_findings
        +list~Dependency~ dependencies
        +list~DependencyFinding~ dependency_findings
        +IngestStats stats
        +total_findings() int
        +severity_counts() dict
    }
    class SecretFinding {
        +str rule
        +str severity
        +str relpath
        +int line
        +str redacted
        +str fingerprint
    }
    class SinkFinding {
        +str category
        +str rule
        +str cwe
        +str owasp
        +int line
    }
    class TaintFinding {
        +str vuln_type
        +str sink
        +str cwe
        +int line
    }
    class IdorFinding {
        +str handler
        +str lookup
        +float confidence
    }
    class MisconfigFinding {
        +str category
        +str rule
        +str cwe
    }
    class RouteFinding {
        +Route route
        +str reason
    }
    class DependencyFinding {
        +Dependency dependency
        +list~Vuln~ vulns
        +str severity
    }
    class Vuln {
        +str id
        +str severity
        +str url
        +cve() str
    }
    class OsvClient {
        +query(deps) dict
    }
    class ReportContext {
        +str audit_id
        +bool is_demo
        +list~ReportFinding~ findings
        +severity_counts()
        +default_executive_summary() str
    }
    class ReportFinding {
        +str type
        +Severity severity
        +FindingStatus status
        +str cwe
        +str cve
        +str owasp_category
        +str remediation
    }

    ScanResult o-- SecretFinding
    ScanResult o-- RouteFinding
    ScanResult o-- SinkFinding
    ScanResult o-- TaintFinding
    ScanResult o-- IdorFinding
    ScanResult o-- MisconfigFinding
    ScanResult o-- DependencyFinding
    DependencyFinding o-- Vuln
    OsvClient ..> Vuln : produces
    ScanResult ..> ReportContext : scan_to_report_context()
    ReportContext o-- ReportFinding
```

ORM models (`backend/app/models/`), used by the implemented auth API and reserved for
the planned audit pipeline:

```mermaid
classDiagram
    class User { +UUID id; +str email; +str password_hash; +UserRole role }
    class Target { +UUID id; +str url; +dict scope; +TargetStatus status }
    class AuthorizationRecord { +bool confirmed; +str statement; +datetime timestamp }
    class SecurityAudit { +AuditStatus status; +int progress; +bool is_demo }
    class ReconnaissanceResult { +list endpoints; +list technologies }
    class Vulnerability { +str type; +Severity severity; +FindingStatus status; +str cwe }
    class SecurityReport { +str report_html; +str report_path }
    class AuditLog { +str agent; +str action; +str message }

    User "1" --> "*" Target
    User "1" --> "*" SecurityAudit
    Target "1" --> "*" AuthorizationRecord
    Target "1" --> "*" SecurityAudit
    SecurityAudit "1" --> "0..1" ReconnaissanceResult
    SecurityAudit "1" --> "*" Vulnerability
    SecurityAudit "1" --> "0..1" SecurityReport
    SecurityAudit "1" --> "*" AuditLog
```
