"""Tests for Django and NestJS route + authorization extraction."""

from __future__ import annotations

from app.analysis.routes import extract_routes, route_findings
from app.analysis.taint import analyze_taint

# --------------------------------------------------------------------------- Django


def _find(findings, method, path_contains):
    return next(
        (f for f in findings if f.route.method == method and path_contains in f.route.path), None
    )


DRF_UNPROTECTED = """
from rest_framework.decorators import api_view
@api_view(["POST"])
def create_user(request):
    return Response()
"""

DRF_PROTECTED = """
from rest_framework.decorators import api_view, permission_classes
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_user(request):
    return Response()
"""

DRF_ALLOWANY = """
@api_view(["POST"])
@permission_classes([AllowAny])
def create_user(request):
    return Response()
"""

CBV_UNPROTECTED = """
class UserViewSet(ModelViewSet):
    def create(self, request):
        return Response()
    def destroy(self, request, pk):
        return Response()
"""

CBV_PROTECTED = """
class UserViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    def create(self, request):
        return Response()
"""

CBV_MIXIN = """
class AdminView(LoginRequiredMixin, View):
    def post(self, request):
        return Response()
"""


def test_drf_function_view_routes() -> None:
    routes = extract_routes("views.py", DRF_UNPROTECTED)
    assert routes and routes[0].method == "POST" and routes[0].framework == "django"
    assert not routes[0].protected


def test_drf_permission_classes_is_guard() -> None:
    assert all(r.protected for r in extract_routes("views.py", DRF_PROTECTED))


def test_drf_allowany_is_not_guard() -> None:
    assert not any(r.protected for r in extract_routes("views.py", DRF_ALLOWANY))


def test_cbv_methods_detected_and_flagged() -> None:
    findings = route_findings(extract_routes("views.py", CBV_UNPROTECTED))
    assert _find(findings, "POST", "UserViewSet") is not None  # create -> POST
    assert _find(findings, "DELETE", "UserViewSet") is not None  # destroy -> DELETE


def test_cbv_permission_classes_protects() -> None:
    assert not route_findings(extract_routes("views.py", CBV_PROTECTED))


def test_cbv_login_mixin_protects() -> None:
    assert not route_findings(extract_routes("views.py", CBV_MIXIN))


def test_drf_function_view_taint_from_url_kwarg() -> None:
    # pk is a URL kwarg (user input) flowing into a raw SQL query.
    src = (
        "from rest_framework.decorators import api_view\n"
        "@api_view(['GET'])\n"
        "def get_user(request, pk):\n"
        "    return connection.cursor().execute('SELECT * FROM u WHERE id=' + pk)\n"
    )
    assert any(f.vuln_type == "sql_injection" for f in analyze_taint("v.py", src))


# --------------------------------------------------------------------------- NestJS

NEST_UNPROTECTED = """
@Controller('users')
export class UsersController {
  @Post('admin')
  create(@Body() dto) { return this.svc.create(dto); }
}
"""

NEST_METHOD_GUARD = """
@Controller('users')
export class UsersController {
  @UseGuards(AuthGuard)
  @Post('admin')
  create(@Body() dto) { return this.svc.create(dto); }
}
"""

NEST_CLASS_GUARD = """
@Controller('users')
@UseGuards(AuthGuard)
export class UsersController {
  @Delete(':id')
  remove(@Param('id') id) { return this.svc.remove(id); }
}
"""

NEST_PUBLIC_OVERRIDE = """
@Controller('users')
@UseGuards(AuthGuard)
export class UsersController {
  @Public()
  @Post('admin')
  create(@Body() dto) { return this.svc.create(dto); }
}
"""


def test_nest_unprotected_flagged() -> None:
    routes = extract_routes("users.controller.ts", NEST_UNPROTECTED)
    assert routes and routes[0].framework == "nestjs"
    assert routes[0].method == "POST" and routes[0].path == "/users/admin"
    assert _find(route_findings(routes), "POST", "/users/admin") is not None


def test_nest_method_guard_protects() -> None:
    assert not route_findings(extract_routes("users.controller.ts", NEST_METHOD_GUARD))


def test_nest_class_guard_protects() -> None:
    assert not route_findings(extract_routes("users.controller.ts", NEST_CLASS_GUARD))


def test_nest_public_override_flagged() -> None:
    # @Public() opts a method out of the class guard -> flagged again.
    assert route_findings(extract_routes("users.controller.ts", NEST_PUBLIC_OVERRIDE))


def test_nest_prefix_and_subpath_joined() -> None:
    routes = extract_routes(
        "c.ts", "@Controller('api/v1')\nclass C {\n  @Get('items')\n  f(){}\n}\n"
    )
    assert routes[0].path == "/api/v1/items"
