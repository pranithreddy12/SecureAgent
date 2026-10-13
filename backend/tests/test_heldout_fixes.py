"""Fixes made after scoring pygoat and juice-shop (applications no detector had been designed on).

Each case pairs the planted pattern with the nearest safe form."""

from __future__ import annotations

import textwrap

from app.analysis.extra_detectors import insecure_session_cookie  # noqa: F401  (import check)
from app.analysis.routes import extract_routes, route_findings
from app.analysis.secrets import scan_text
from app.analysis.sinks import scan_sinks
from app.analysis.taint import analyze_taint, analyze_taint_project


def src(text: str) -> str:
    return textwrap.dedent(text)


def py(code: str) -> set[str]:
    return {f.vuln_type for f in analyze_taint("app.py", src(code))}


def js(code: str, name: str = "app.ts") -> set[str]:
    return {f.vuln_type for f in analyze_taint_project([(name, src(code))])}


def cats(path: str, code: str) -> list[str]:
    return [f.category for f in scan_sinks(path, src(code))]


# ------------------------------------------------------------------ Python


def test_library_eval_of_request_input_is_code_injection_but_model_eval_is_not():
    bad = """
        def lab(request):
            expr = request.POST.get("function")
            return ImageMath.eval(expr, img=img)
    """
    assert "code_injection" in py(bad)
    benign = """
        def run(request):
            model.eval()
            return ast.literal_eval(request.POST.get("x"))
    """
    assert "code_injection" not in py(benign)


def test_sax_external_entities_feature_is_xxe():
    bad = """
        from xml.sax import make_parser
        from xml.sax.handler import feature_external_ges
        def parse(body):
            parser = make_parser()
            parser.setFeature(feature_external_ges, True)
    """
    assert "xxe" in cats("a.py", bad)
    off = bad.replace("feature_external_ges, True", "feature_external_ges, False")
    assert "xxe" not in cats("a.py", off)


def test_cookie_named_cookie_holding_the_username_is_an_unsigned_session():
    bad = """
        def login(request, username):
            expire = now()
            cookie = f"{username}|{expire}"
            response.set_cookie("cookie", cookie)
    """
    assert "insecure_session_cookie" in cats("a.py", bad)
    unrelated = """
        def banner(response):
            response.set_cookie("cookie", "accepted")
    """
    assert "insecure_session_cookie" not in cats("a.py", unrelated)


def test_django_create_user_hashes_so_it_is_not_plaintext_storage():
    ok = """
        def register(username, password):
            User.objects.create_user(username=username, password=password)
    """
    assert "plaintext_password" not in cats("a.py", ok)
    bad = """
        def register(name, passwd):
            AuthLogin.objects.create(name=name, password=passwd)
    """
    assert "plaintext_password" in cats("a.py", bad)


def test_is_authenticated_check_in_a_handler_or_class_view_is_a_guard():
    func = """
        def lab(request):
            if request.user.is_authenticated:
                return render(request, "x.html")
            return redirect("login")
    """
    assert (
        route_findings(
            extract_routes(
                "views.py",
                src(
                    func
                    + '\n@app.route("/x", methods=["POST"])\n'
                    + func.replace("def lab", "def x")
                ),
            )
        )
        == []
    )
    cbv = """
        class Challenge(View):
            def delete(self, request, challenge):
                if not request.user.is_authenticated:
                    return redirect("login")
                return JsonResponse({})
    """
    assert route_findings(extract_routes("views.py", src(cbv))) == []
    unguarded = """
        class Challenge(View):
            def delete(self, request, challenge):
                return JsonResponse({})
    """
    assert route_findings(extract_routes("views.py", src(unguarded)))


# ------------------------------------------------------------------ TypeScript / JavaScript


def test_ts_type_annotation_and_alias_chains_carry_taint():
    sqli = """
        export function search () {
          return (req: Request, res: Response) => {
            let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
            models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)
          }
        }
    """
    assert "sql_injection" in js(sqli)
    redirect = """
        export function redirect () {
          return (req: Request, res: Response) => {
            const query = req.query
            const toUrl: string = query.to as string
            res.redirect(toUrl)
          }
        }
    """
    assert "open_redirect" in js(redirect)
    fixed_target = """
        export function home () {
          return (req: Request, res: Response) => {
            res.redirect('/home')
          }
        }
    """
    assert "open_redirect" not in js(fixed_target)


def test_destructured_request_handler_parameters_are_input():
    bad = """
        export function servePublicFiles () {
          return ({ params, query }: Request, res: Response, next: NextFunction) => {
            const file = params.file
            res.sendFile(path.resolve('ftp/', file))
          }
        }
    """
    assert "path_traversal" in js(bad)


def test_vm_run_in_context_with_request_data_is_code_injection():
    bad = """
        export function b2b () {
          return (req: Request, res: Response) => {
            const body = req.body
            const orderLinesData = body.orderLinesData || ''
            vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
          }
        }
    """
    assert "code_injection" in js(bad)


def test_constant_arguments_are_not_injection():
    header = "const { execSync } = require('child_process')\n"
    for line in (
        "const root = execSync('npm root -g', { encoding: 'utf8' })\n",
        "const f = new Function('specifier', 'return import(specifier)')\n",
    ):
        found = scan_sinks("a.ts", header + line)
        assert [f for f in found if f.category.endswith("injection")] == []
    dynamic = header + "const out = execSync('ping ' + host)\n"
    assert [f for f in scan_sinks("a.ts", dynamic) if f.category == "command_injection"]


def test_js_sink_rules_added_for_heldout_apps():
    assert "weak_hash" in cats("a.ts", "const h = crypto.createHash('md5').update(d)\n")
    assert "weak_hash" not in cats("a.ts", "const h = crypto.createHash('sha256').update(d)\n")
    assert "xss_sink" in cats("a.ts", "this.html = this.sanitizer.bypassSecurityTrustHtml(v)\n")
    assert "xxe" in cats("lib/xml.ts", "const o = libxml2.ParseOption.XML_PARSE_NOENT | x\n")
    # comparing innerHTML is not assigning it
    assert "xss_sink" not in cats("a.ts", "if (element.innerHTML === value) { return }\n")


def test_hardcoded_key_literal_in_signing_calls():
    mac = "const hmac = (d) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(d)\n"
    assert [f.rule for f in scan_text("lib/insecurity.ts", mac)] == [
        "Hardcoded key passed to a signing/MAC call"
    ]
    jwt_sign = "const t = jwt.sign(payload, 'super-secret-signing-key')\n"
    assert scan_text("a.ts", jwt_sign)
    env_key = "const t = jwt.sign(payload, process.env.JWT_KEY)\n"
    assert scan_text("a.ts", env_key) == []


def test_nosql_filter_field_from_request_across_lines():
    bad = """
        db.reviewsCollection.update( // comment
          { _id: req.body.id },
          { $set: { message: req.body.message } }
        )
    """
    assert "nosql_injection" in js(bad)
    typed = "db.reviewsCollection.update({ _id: String(id) }, { $set: { a: 1 } })\n"
    assert "nosql_injection" not in js(typed)
