"""Static source-code analysis for SecureAgent (grey-box engine, ADR-008).

Read-only: these modules never execute, import, or install anything from an analysed
project. Secret values are redacted on capture and never stored or transmitted in full.
"""
