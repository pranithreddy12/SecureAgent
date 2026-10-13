# ADR-027: Django `urls.py` view functions are handlers

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "proceed with the Django urls.py handler fix")

## Context

ADR-026 measured 0 of 11 annotated IDORs in django.nV: plain `def view(request, ...)` functions are wired
in `urls.py` and carry no decorator, so no analyser treated them as request handlers.

## Decision

- A pre-pass reads every `urls.py` and collects view names from `url()`, `path()`, `re_path()` calls
  (dotted references and string views; `include(...)` and `.as_view()` are skipped). They join the
  handler-name set already used for OpenAPI `operationId` handlers (`SPEC_HANDLERS`).
- A redirect whose argument starts with a literal same-site path (`'/x/' + value`, not `//`) is not an
  open redirect.

## Result

django.nV 5/17 -> 15/17 found; 36 findings (45 before the redirect rule). Overall 170/207 planted (82%,
tuned-on). Benchmark 97% / 97%; backend 567 passed.

## Not claimed

Handler detection is by *function name* across the project, so an unrelated function that shares a
view's name in another module is also treated as a handler. Class-based views and `include()`d URLconfs
are not followed. Unmeasured on an unseen Django project.
