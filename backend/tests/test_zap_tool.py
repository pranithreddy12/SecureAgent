import re

from app.schemas.pipeline import TargetScope
from app.tools.zap_tool import _include_regex


def test_include_regex_matches_a_host_with_a_port():
    scope = TargetScope(allowed_hosts=["juice-shop"], allow_private=True)
    regex = _include_regex(scope)
    assert re.match(regex, "http://juice-shop:3000/")
    assert re.match(regex, "http://juice-shop/")
    assert not re.match(regex, "http://evil.example.com/")
