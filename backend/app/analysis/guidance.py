"""Per-finding-type guidance for whoever (or whatever) judges a finding: its ceiling and its checks.

Static analysis produces review items, and a downstream assistant tends to inflate them (a stdlib
XML parse became "XXE -> SSRF -> file disclosure"). Each type therefore carries:

- ``impact_ceiling``: the worst realistic outcome this *kind* of finding can have;
- ``not_claimed``: what the finding does NOT establish -- do not claim it;
- ``verify_with``: the questions that settle whether it is real, answerable from the code shown.

Hand-written and deliberately short. ``DEFAULT`` covers any type without an entry; a test requires
every type the detectors can emit to have its own.
"""

# ruff: noqa: E501  (prose strings read better unwrapped)
from __future__ import annotations

from typing import TypedDict


class Guidance(TypedDict):
    impact_ceiling: str
    not_claimed: str
    verify_with: list[str]


def _g(impact: str, not_claimed: str, *checks: str) -> Guidance:
    return {"impact_ceiling": impact, "not_claimed": not_claimed, "verify_with": list(checks)}


_INJECTION_NOT = (
    "That the value is attacker-controlled in production, or that exploitation was shown."
)

GUIDANCE: dict[str, Guidance] = {
    "sql_injection": _g(
        "Read or modify database contents the application's DB user can reach.",
        _INJECTION_NOT,
        "Is the tainted part a VALUE (bound parameter) or an identifier (table/column/ORDER BY)?",
        "Are identifiers taken from a fixed whitelist or config rather than from the request?",
        "Does the request value pass a cast/allow-list before reaching the query string?",
    ),
    "command_injection": _g(
        "Run commands as the application's OS user.",
        _INJECTION_NOT,
        "Is shell=True (or a shell string) used, or an argument list without a shell?",
        "Is the value quoted (shlex.quote) or checked against an allow-list first?",
    ),
    "code_injection": _g(
        "Execute arbitrary code in the application process.",
        _INJECTION_NOT,
        "Can request data reach eval/exec/compile/template compilation unchanged?",
        "Is the input restricted to a fixed set of expressions or a safe literal parser?",
    ),
    "ssrf": _g(
        "Make the server request internal or attacker-chosen URLs (metadata, intranet).",
        "That internal hosts are reachable from the server, or that a response is returned to the user.",
        "Is the host allow-listed or the URL built from a fixed base?",
        "Are redirects followed, and is the response body returned to the caller?",
    ),
    "path_traversal": _g(
        "Read or write files outside the intended directory.",
        _INJECTION_NOT,
        "Is the path joined to a fixed base and then resolved and checked to stay inside it?",
        "Is the filename sanitised (secure_filename / basename) or generated server-side?",
    ),
    "open_redirect": _g(
        "Send users to an attacker-chosen site (phishing aid).",
        "Any server-side impact; this affects users, not the server.",
        "Is the target restricted to relative paths or an allow-list of hosts?",
    ),
    "insecure_deserialization": _g(
        "Code execution if the data source is untrusted.",
        "That the data is attacker-controlled; trusted internal data is common.",
        "Where does the pickled/loaded data come from: user upload, network, or the app's own store?",
    ),
    "xxe": _g(
        "Local file read or SSRF through external entities, if the parser resolves them.",
        "That the XML is attacker-controlled.",
        "Is entity resolution/network access disabled on the parser?",
        "Is the XML from a trusted source?",
    ),
    "xml_entity_expansion": _g(
        "Denial of service by entity-expansion (memory/CPU).",
        "XXE, SSRF or file disclosure: the standard-library parser does not load external entities.",
        "Is the XML from an untrusted source (user upload, third-party feed)?",
        "Is defusedxml (or a size cap) already in use?",
    ),
    "xss_sink": _g(
        "Script execution in a visitor's browser.",
        "That the value is attacker-controlled or unsanitised.",
        "Is the value escaped/sanitised, or a framework auto-escape in effect?",
    ),
    "hardcoded_secret": _g(
        "Use of the credential by anyone who can read the source or its history.",
        "That the value is live; it may be a placeholder, a test key or already rotated.",
        "Is it a real credential for a real service (not an example, test fixture or public client key)?",
        "Is the file git-ignored, and was the value ever committed?",
    ),
    "weak_hash": _g(
        "Collisions or fast brute force if used for passwords or integrity.",
        "That it protects anything sensitive; MD5/SHA1 for cache keys or ETags is harmless.",
        "What is the hash used for: passwords/signatures, or a non-security checksum?",
    ),
    "disabled_tls_verification": _g(
        "Man-in-the-middle on that connection.",
        "That the connection carries sensitive data or runs outside tests.",
        "Is the flag set only in tests/dev, or conditional on an environment variable?",
    ),
    "jwt_verification_disabled": _g(
        "Forged tokens accepted, so authentication bypass.",
        "That the code path guards real resources.",
        "Is signature verification really off (verify_signature False / algorithms none) on a live path?",
    ),
    "permissive_cors": _g(
        "Another site's script can read authenticated responses, if credentials are allowed.",
        "That cookies/credentials are accepted with the wildcard origin.",
        "Is allow_credentials true together with a wildcard or reflected origin?",
    ),
    "csrf_disabled": _g(
        "State-changing requests forged from another site, if sessions use cookies.",
        "That the app uses cookie-based sessions.",
        "Does authentication use cookies, or a bearer token header that browsers do not attach?",
    ),
    "debug_enabled": _g(
        "Interactive debugger / stack traces exposed, leaking code and secrets.",
        "That debug is on in production.",
        "Is debug set from configuration for production, or hardcoded True?",
    ),
    "insecure_temp_file": _g(
        "Another local user may read or replace the file (race).",
        "A remote impact.",
        "Is the temp file created with mkstemp/NamedTemporaryFile, in a private directory?",
    ),
    "sensitive_data_in_log": _g(
        "Credentials or personal data readable by whoever can read the logs.",
        "That the logs are exposed beyond operators.",
        "Does the logged value actually contain a secret or personal data at runtime?",
    ),
    "swallowed_exception": _g(
        "Failures go unnoticed; security checks may silently not run.",
        "A direct vulnerability.",
        "Does the guarded code perform a security-relevant action whose failure is hidden?",
    ),
    "idor": _g(
        "Read or change another user's object by changing an id.",
        "That an ownership check is missing; it may be enforced in a middleware, query scope or helper.",
        "Is the object filtered by the current user (owner column, tenant scope) anywhere on this path?",
        "Does a decorator, dependency or the data layer enforce ownership?",
    ),
    "missing_function_level_authorization": _g(
        "An unauthenticated or low-privileged caller reaching the function.",
        "That the route is actually public; global middleware or the gateway may enforce auth.",
        "Is authentication applied globally (middleware, router include, API gateway)?",
        "Is the endpoint meant to be public (health, login, public read)?",
    ),
    "inconsistent_authorization": _g(
        "A sibling route lacking the guard its neighbours have.",
        "That the unguarded route is wrong; it may be intentionally public.",
        "Should this route require the same guard as its siblings?",
    ),
    "mass_assignment": _g(
        "A client sets fields it should not (role, price, ownership).",
        "That sensitive fields are actually present on the model.",
        "Does the bound payload include privileged fields, and are they excluded or read-only?",
    ),
    "client_trusted_privilege": _g(
        "Privilege escalation by sending a role/admin flag.",
        "That the field is honoured; the server may overwrite it later.",
        "Is the privileged value taken from the request body and stored without a server-side check?",
    ),
    "client_trusted_value": _g(
        "Price/amount/quantity tampering.",
        "That the amount is charged or fulfilled.",
        "Is the value recomputed server-side from trusted data before use?",
    ),
    "workflow_order": _g(
        "Skipping a required step (pay, approve, verify).",
        "That the skipped step is actually required by the business.",
        "Is the state change guarded by a check of the previous state?",
    ),
    "intent_violation": _g(
        "Breach of a rule the developer wrote down in the intent file.",
        "A confirmed vulnerability; it states code differs from declared intent.",
        "Is the declared rule still correct, and does the flagged code really break it?",
    ),
    "vulnerable_dependency": _g(
        "Whatever the advisory describes, if the vulnerable code path is used.",
        "That the application calls the vulnerable function.",
        "Is the vulnerable API/feature used? Is a fixed version available and compatible?",
    ),
}

DEFAULT: Guidance = _g(
    "Unknown; treat as a review item.",
    "That the issue is exploitable or confirmed.",
    "Read the code at the location and decide whether the described condition really holds.",
)


def guidance_for(finding_type: str) -> Guidance:
    return GUIDANCE.get(finding_type, DEFAULT)
