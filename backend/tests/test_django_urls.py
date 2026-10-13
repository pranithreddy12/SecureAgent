"""Django function views wired through urls.py (fourth untouched set: 0 of 11 IDORs)."""

from __future__ import annotations

import textwrap

from app.analysis.access_control import analyze_access_control
from app.analysis.openapi_spec import SPEC_HANDLERS, parse_django_urls
from app.analysis.scanner import scan_repo
from app.analysis.taint import analyze_taint

URLS = r"""
urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^(?P<project_id>\d+)/delete/$', views.project_delete),
    url(r'^api/', include('api.urls')),
    path('p/<int:pk>/', views.detail, name='detail'),
    url(r'^c/', views.ClassView.as_view()),
    url(r'^old/', 'app.views.old_style'),
)
"""

VIEWS = """
def project_delete(request, project_id):
    proj = Project.objects.get(pk=project_id)
    proj.delete()
    return redirect('/taskManager/' + project_id + '/')

def logout_view(request):
    return redirect(request.GET.get('redirect', '/'))
"""


def test_urlpatterns_name_the_view_functions():
    assert parse_django_urls(textwrap.dedent(URLS)) == {
        "index",
        "project_delete",
        "detail",
        "old_style",
    }
    assert parse_django_urls("x = 1\n") == set()


def test_undecorated_view_is_a_handler_only_when_urls_wires_it(tmp_path):
    views = textwrap.dedent(VIEWS)
    token = SPEC_HANDLERS.set(frozenset())
    try:
        assert analyze_access_control("views.py", views) == []  # not a handler: nothing seen
    finally:
        SPEC_HANDLERS.reset(token)
    token = SPEC_HANDLERS.set(frozenset({"project_delete"}))
    try:
        found = analyze_access_control("views.py", views)
    finally:
        SPEC_HANDLERS.reset(token)
    assert [f.handler for f in found] == ["project_delete"]


def test_scan_repo_reads_urls_py_end_to_end(tmp_path):
    (tmp_path / "views.py").write_text(textwrap.dedent(VIEWS), encoding="utf-8")
    (tmp_path / "urls.py").write_text(textwrap.dedent(URLS), encoding="utf-8")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert any(f.handler == "project_delete" for f in result.idor_findings)
    kinds = {f.vuln_type for f in result.taint_findings}
    assert "open_redirect" in kinds  # logout_view redirects to ?redirect=
    redirects = [f for f in result.taint_findings if f.vuln_type == "open_redirect"]
    assert len(redirects) == 1  # the '/taskManager/' + id redirect is a fixed same-site path


def test_literal_site_path_prefix_is_not_an_open_redirect_but_host_prefix_is():
    ok = "def v(request):\n    return redirect('/app/' + request.GET['id'] + '/')\n"
    assert "open_redirect" not in {f.vuln_type for f in analyze_taint("a.py", _handler(ok))}
    bad = "def v(request):\n    return redirect('//' + request.GET['host'])\n"
    assert "open_redirect" in {f.vuln_type for f in analyze_taint("a.py", _handler(bad))}


def _handler(code: str) -> str:
    return "@app.route('/x')\n" + code
