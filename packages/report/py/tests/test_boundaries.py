"""Static guards: the agent carries no environment knowledge and makes no network calls."""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "ca3p_report"
FORBIDDEN_MODULES = {"socket", "urllib", "http", "requests", "httpx", "ftplib", "smtplib"}


def sources():
    return sorted(SRC.rglob("*.py"))


def test_no_environment_variable_reads():
    for path in sources():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            name = node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", None)
            imported = [a.name for a in node.names] if isinstance(node, ast.ImportFrom) else []
            assert name not in {"environ", "getenv", "environb"}, path
            assert not {"environ", "getenv", "environb"} & set(imported), path


def test_no_network_modules():
    for path in sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in FORBIDDEN_MODULES, (path, name)


def test_no_hardcoded_absolute_paths():
    for path in sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not node.value.startswith(("/app", "/opt", "/data", "/var", "/tmp")), (
                    path,
                    node.value,
                )
