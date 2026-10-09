"""Render a ReportContext to HTML (Jinja2, autoescaped) and PDF (WeasyPrint)."""

from datetime import datetime
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from app.schemas.report import NO_CVE, NO_CVSS, ReportContext

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _dt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "—"


def _pct(value: float) -> str:
    return f"{value:.0%}"


@lru_cache
def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        # Evidence and target content are untrusted: always escape.
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["dt"] = _dt
    env.filters["pct"] = _pct
    env.globals.update(no_cve=NO_CVE, no_cvss=NO_CVSS)
    return env


def render_html(ctx: ReportContext) -> str:
    return _env().get_template("report.html").render(r=ctx)


def render_pdf(html: str) -> bytes:
    # Imported lazily: WeasyPrint needs native Pango libraries (present in the Docker
    # image); HTML rendering keeps working where they are missing.
    from weasyprint import HTML

    return HTML(string=html).write_pdf()
