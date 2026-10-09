"""Tests for Django settings misconfiguration and class-based-view taint / IDOR."""

from __future__ import annotations

from app.analysis.access_control import analyze_access_control
from app.analysis.misconfig import scan_misconfig
from app.analysis.taint import analyze_taint, analyze_taint_project


def mcats(src: str) -> set[str]:
    return {f.category for f in scan_misconfig("settings.py", src)}


def mrules(src: str) -> set[str]:
    return {f.rule for f in scan_misconfig("settings.py", src)}


# --------------------------------------------------------------- settings


def test_django_insecure_cookie_flags() -> None:
    assert "insecure_cookie" in mcats("SESSION_COOKIE_SECURE = False\n")
    assert "insecure_cookie" in mcats("CSRF_COOKIE_SECURE = False\n")
    assert "insecure_cookie" in mcats("SESSION_COOKIE_HTTPONLY = False\n")


def test_django_secure_cookie_flags_not_flagged() -> None:
    assert "insecure_cookie" not in mcats("SESSION_COOKIE_SECURE = True\n")


def test_django_cors_allow_all() -> None:
    assert "permissive_cors" in mcats("CORS_ALLOW_ALL_ORIGINS = True\n")
    assert "permissive_cors" in mcats("CORS_ORIGIN_ALLOW_ALL = True\n")
    assert "permissive_cors" not in mcats("CORS_ALLOW_ALL_ORIGINS = False\n")


def test_django_csrf_middleware_removed() -> None:
    src = (
        "MIDDLEWARE = [\n"
        "    'django.middleware.security.SecurityMiddleware',\n"
        "    'django.contrib.sessions.middleware.SessionMiddleware',\n"
        "    'django.middleware.common.CommonMiddleware',\n"
        "]\n"
    )
    assert "CsrfViewMiddleware missing from MIDDLEWARE" in mrules(src)


def test_django_csrf_middleware_present_is_fine() -> None:
    src = (
        "MIDDLEWARE = [\n"
        "    'django.contrib.sessions.middleware.SessionMiddleware',\n"
        "    'django.middleware.csrf.CsrfViewMiddleware',\n"
        "]\n"
    )
    assert "CsrfViewMiddleware missing from MIDDLEWARE" not in mrules(src)


def test_unrelated_middleware_list_not_flagged() -> None:
    # Not a Django settings list (e.g. an app's own pipeline) -> do not guess.
    assert "csrf_disabled" not in mcats("MIDDLEWARE = ['logging', 'metrics']\n")


# --------------------------------------------------------------- class-based views

CBV_TAINT = """
from django.views import View
class Search(View):
    def get(self, request, name):
        return connection.cursor().execute("SELECT * FROM u WHERE n='" + name + "'")
"""

CBV_REQUEST_INPUT = """
from rest_framework.views import APIView
import os
class Run(APIView):
    def post(self, request):
        os.system(request.data.get("cmd"))
"""

CBV_IDOR = """
from rest_framework.views import APIView
class AccountView(APIView):
    def get(self, request, pk):
        return Account.objects.get(pk=pk)
"""

CBV_SCOPED_QUERYSET = """
from rest_framework.viewsets import ModelViewSet
class AccountViewSet(ModelViewSet):
    def get_queryset(self):
        return Account.objects.filter(owner=self.request.user)
    def retrieve(self, request, pk):
        return Account.objects.get(pk=pk)
"""

CBV_SCOPED_INLINE = """
from rest_framework.views import APIView
class AccountView(APIView):
    def get(self, request, pk):
        return Account.objects.filter(pk=pk, owner=request.user).first()
"""

TWO_VIEWS_SAME_METHOD_NAME = """
from django.views import View
import os
class Safe(View):
    def get(self, request):
        return "ok"
class Danger(View):
    def get(self, request, cmd):
        os.system(cmd)
"""


def test_cbv_url_kwarg_taint() -> None:
    assert any(f.vuln_type == "sql_injection" for f in analyze_taint("v.py", CBV_TAINT))


def test_cbv_request_data_taint() -> None:
    assert any(f.vuln_type == "command_injection" for f in analyze_taint("v.py", CBV_REQUEST_INPUT))


def test_cbv_idor_flagged() -> None:
    findings = analyze_access_control("v.py", CBV_IDOR)
    assert findings and findings[0].handler == "get"


def test_cbv_get_queryset_scoping_suppresses_idor() -> None:
    assert analyze_access_control("v.py", CBV_SCOPED_QUERYSET) == []


def test_cbv_inline_owner_filter_suppresses_idor() -> None:
    assert analyze_access_control("v.py", CBV_SCOPED_INLINE) == []


def test_same_method_name_in_two_views_both_analysed() -> None:
    # `get` exists in both classes; the vulnerable one must not be dropped by name collision.
    findings = analyze_taint("v.py", TWO_VIEWS_SAME_METHOD_NAME)
    assert any(f.vuln_type == "command_injection" for f in findings)


def test_cbv_works_through_project_pass() -> None:
    findings = analyze_taint_project([("views.py", CBV_TAINT)])
    assert any(f.vuln_type == "sql_injection" for f in findings)


def test_non_view_class_methods_are_not_handlers() -> None:
    src = "class Helper:\n    def get(self, name):\n        os.system(name)\n"
    assert analyze_taint("v.py", src) == []
