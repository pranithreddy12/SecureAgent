"""A small, conservative .gitignore matcher.

Used only to *explain* findings: a secret in a file that git ignores is not part of the repository
(it is a local file such as ``.env``), which changes how it should be read -- it is still sensitive,
but it is not "committed". It is deliberately not a full implementation of gitignore semantics:

- supports ``#`` comments, blank lines, ``dir/`` (directory-only), leading ``/`` (anchored),
  ``*`` / ``?`` / ``[]`` globs and ``**``;
- negation (``!pattern``) is honoured in order, last match wins, like git;
- nested ``.gitignore`` files and ``.git/info/exclude`` are not read.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class _Rule:
    pattern: str
    anchored: bool
    dir_only: bool
    negated: bool


def parse_gitignore(text: str) -> list[_Rule]:
    rules: list[_Rule] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        line = line.strip() if not line.endswith("\\ ") else line
        negated = line.startswith("!")
        if negated:
            line = line[1:]
        dir_only = line.endswith("/")
        line = line.rstrip("/")
        anchored = line.startswith("/") or "/" in line
        line = line.lstrip("/")
        if line:
            rules.append(_Rule(line, anchored, dir_only, negated))
    return rules


def _glob(pattern: str, path: str) -> bool:
    # fnmatch treats '*' as matching '/', so translate '**' and '*' explicitly.
    regex = ""
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            regex += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            regex += ".*"
            i += 2
        elif c == "*":
            regex += "[^/]*"
            i += 1
        elif c == "?":
            regex += "[^/]"
            i += 1
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                regex += re.escape(c)
                i += 1
            else:
                regex += "[" + pattern[i + 1 : j].replace("\\", "\\\\") + "]"
                i = j + 1
        else:
            regex += re.escape(c)
            i += 1
    return re.fullmatch(regex, path) is not None


class GitIgnore:
    def __init__(self, text: str = "") -> None:
        self._rules = parse_gitignore(text)

    @classmethod
    def from_root(cls, root: str | os.PathLike[str]) -> GitIgnore:
        try:
            with open(os.path.join(root, ".gitignore"), encoding="utf-8", errors="replace") as fh:
                return cls(fh.read())
        except OSError:
            return cls("")

    def __bool__(self) -> bool:
        return bool(self._rules)

    def is_ignored(self, relpath: str) -> bool:
        """True if ``relpath`` (posix, relative to the root) or any parent directory is ignored."""
        parts = relpath.replace("\\", "/").split("/")
        # git ignores a path if it, or a parent directory, matches (a file in an ignored dir cannot
        # be re-included), so test each prefix; the final component is a file.
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            is_dir = i < len(parts)
            if self._matches(prefix, parts[i - 1], is_dir):
                return True
        return False

    def _matches(self, path: str, name: str, is_dir: bool) -> bool:
        result = False
        for rule in self._rules:
            if rule.dir_only and not is_dir:
                continue
            hit = (
                _glob(rule.pattern, path)
                if rule.anchored
                else (_glob(rule.pattern, name) or fnmatch.fnmatchcase(name, rule.pattern))
            )
            if hit:
                result = not rule.negated
        return result
