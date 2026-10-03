# ADR-007: Report rendering — Jinja2 HTML + WeasyPrint PDF

- **Date:** 2026-10-03
- **Status:** Accepted

## Context
The Report Agent must produce a professional HTML report and a downloadable PDF with
19 required sections. Report content includes untrusted data (target responses,
evidence) and must never invent identifiers (CVE/CVSS). Development happens on
Windows; the deployment target is Docker (Debian).

## Decision
- A Pydantic `ReportContext` (`app/schemas/report.py`) is the only input. Derived
  views (severity counts, false-positive split, OWASP/CWE grouping, deterministic
  executive summary) are computed in Python, not in the template.
- One Jinja2 template (`app/reports/templates/report.html`) with autoescaping and
  `StrictUndefined`; the same HTML serves the in-app viewer and the PDF.
- PDF via WeasyPrint (HTML/CSS → PDF; supports `@page` margin boxes for page
  numbers and the DEMO watermark). Native Pango libraries are installed in the
  backend image. On hosts without Pango (Windows dev), HTML rendering still works
  and the PDF test is skipped; PDF output is verified in the container.

## Alternatives
- xhtml2pdf / ReportLab — pure Python, but weak CSS support (no modern layout);
  report quality would suffer.
- Headless Chromium (Playwright) — best fidelity, but adds a ~400 MB browser to the
  backend image.

## Consequences
- Backend image gains Pango/HarfBuzz and a font package.
- Local PDF generation on Windows requires installing GTK/Pango separately.
