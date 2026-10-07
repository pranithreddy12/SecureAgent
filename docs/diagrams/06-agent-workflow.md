# 6. Multi-Agent Workflow Diagram (DESIGNED — not yet implemented)

> This is the academic multi-agent audit pipeline from the specification. It is
> **designed** (`docs/agent-workflow.md`, ADR-001, ADR-003) but **not implemented** —
> it depends on target management (Phases 4–5), which is not built. The PPT
> "Exploitation Agent" is realised here as the controlled, non-destructive
> **Safe Validation Agent** (ADR-003).
>
> The **Code Intelligence** stage below is partially realised today by the
> implemented static-analysis engine (secrets, taint, IDOR, misconfig, deps); the
> grey-box design (ADR-008) folds it into this pipeline.

```mermaid
flowchart TD
    START([Start]) --> AUTH{Authorization<br/>confirmed?}
    AUTH -- no --> FAIL([Audit failed])
    AUTH -- yes --> VAL{Target + source<br/>validation}
    VAL -- invalid --> FAIL
    VAL -- valid --> FAN1[ ]
    FAN1 --> RECON[Reconnaissance Agent]
    FAN1 --> CODE[Code Intelligence<br/>partially implemented]
    RECON --> MODEL[Build Application Model]
    CODE --> MODEL
    MODEL --> FAN2[ ]
    FAN2 --> SCAN[Vulnerability Scanner Agent<br/>ZAP · Nuclei]
    FAN2 --> LOGIC[Business-Logic Reasoning]
    SCAN --> SV{Potential<br/>findings?}
    LOGIC --> SV
    SV -- no --> REPORT[Report Agent]
    SV -- yes --> SAFE[Safe Validation Agent<br/>= Exploitation Agent, non-destructive]
    SAFE --> VALID[Validator Agent<br/>false-positive reduction]
    VALID --> REPORT
    REPORT --> PERSIST[(Persist results)]
    PERSIST --> END([End])

    style CODE stroke-dasharray: 3 3
```

Finding statuses produced by the Validator: `confirmed`, `likely`, `suspicious`,
`false_positive`, `informational`. The implemented static engine already uses these
same statuses honestly (definite misconfig → likely; input-dependent → suspicious;
never confirmed without dynamic/evidence).
