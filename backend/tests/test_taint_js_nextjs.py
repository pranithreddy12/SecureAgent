"""JavaScript/TypeScript taint: Next.js App Router input, Prisma raw SQL, calls split over lines."""

from __future__ import annotations

from app.analysis.taint import analyze_taint


def kinds(src: str, name: str = "route.ts") -> set[str]:
    return {f.vuln_type for f in analyze_taint(name, src)}


def test_request_json_destructure_reaches_prisma_unsafe_raw_sql():
    src = """
export async function POST(request: Request) {
  const { name } = await request.json();
  return Response.json(await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE n = '${name}'`));
}
"""
    assert "sql_injection" in kinds(src)


def test_search_params_reach_a_command():
    src = """
export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q');
  exec('grep ' + q + ' file.txt');
}
"""
    assert "command_injection" in kinds(src)


def test_a_call_split_over_lines_is_one_statement():
    src = """
app.get('/p', (req, res) => {
  const host = req.query.host;
  exec(
    'ping -c 1 ' + host,
    cb
  );
});
"""
    assert "command_injection" in kinds(src, "a.js")


def test_safe_variants_stay_clean():
    assert not kinds("exec(\n  'npm root -g'\n)\n", "a.js")  # constant, split over lines
    assert not kinds("const id = searchParams.get('id');\nconsole.log(id);\n")  # no sink
    assert not kinds(  # a callback body is not part of the sink call
        "db.query('SELECT 1', (err, rows) => {\n  const x = req.query.x;\n  log(x);\n});\n", "a.js"
    )
