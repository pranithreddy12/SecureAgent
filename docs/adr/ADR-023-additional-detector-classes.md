# ADR-023: Detector classes for the planted flaws that had none

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "proceed with the missing detectors")
- **Relates to:** ADR-021, ADR-022 (`docs/evaluation.md`)

## Context

The recall run listed eight planted flaws outside the detector taxonomy: template injection (x3), XPath
injection, reflected XSS in string formatting, NoSQL injection, insecure session design and plaintext
password storage. Without detectors, recall was capped and "no findings" was misleading for those classes.

## Decision

New detectors in `app/analysis/extra_detectors.py`, hooked into the taint engine and the sink visitor:

| Class | Evidence required | Quiet when |
|---|---|---|
| `template_injection` | request input reaches `render_template_string` / `Template(...)` / `from_string`, or is the *receiver* of `.format()`; JS `ejs.render`, `pug.render`, `handlebars.compile` | input is only a template variable; format receiver is a literal |
| `xpath_injection` | request input in `.xpath(expr)`; JS `xpath.select` | input bound as a variable |
| `nosql_injection` | the whole request object passed as a Mongo filter; `$where` with input; JS `$where` built by concatenation / template literal | filter built from validated scalars; constant `$where` |
| `reflected_xss` | a handler returns (or `Response`/`make_response`) an HTML string with a tag literal and unescaped input | `escape()` / `html.escape` / `bleach.clean` wrapped, or no markup in the response |
| `insecure_session_cookie` | `set_cookie("...session/auth/user...", value)` where value is base64/JSON/`str` of the user and no signing/encryption evidence | value comes from a signer, JWT, random token, UUID |
| `plaintext_password` | a password parameter/variable reaches a model constructor, `.password =`, a `password=` keyword to a DB call, or an INSERT/UPDATE, and the function calls no hashing helper | any hash/KDF call in the function (conservative) |
| JS `idor` | `Model.find/findById/destroy/...` with `req.(body|params|query).<x>id` and no owner/tenant/session token in the handler | an owner token is present |

All are `suspicious`-level heuristics with guidance text (`impact_ceiling`, `not_claimed`, `verify_with`)
and review-layer eligibility.

## Result

Recall over all 42 planted flaws: 79% (before) -> 95% (after), on the applications the detectors were
designed against; 0 new findings on 22 real projects.

## Not claimed

- Tuned on the evaluation applications: a design-time look at the code shaped every rule.
- The "any hashing call in the function" rule trades recall for precision; a function that hashes
  something else suppresses the finding.
- `reflected_xss` does not follow strings built in buffers or through templates; `template_injection`
  does not see input arriving through an exception message.
- No detector here has a measured real-world true-positive rate, only a measured absence of false
  positives on 22 projects.
