"""Structured CLI output remains usable with redirected legacy OS encodings."""
import io
import json
from pathlib import Path
import tomllib

import pytest

from sawm_defense.cli import emit


def test_cli_and_distribution_versions_match(capsys):
    from sawm_defense.cli import parser
    with pytest.raises(SystemExit) as stopped:
        parser().parse_args(["--version"])
    assert stopped.value.code == 0
    version = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert capsys.readouterr().out.strip() == f"SAWM Defense {version}"


@pytest.mark.parametrize("encoding", ["ascii", "cp1252", "utf-8"])
def test_emit_preserves_international_paths_in_json(monkeypatch, encoding):
    data = {"path": "C:\\Users\\client\\资料\\contrat.pdf", "message": "Alerte mémoire — مرحبا 🔎"}
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding=encoding)
    monkeypatch.setattr("sys.stdout", stream)
    emit(data)
    stream.flush()
    output = raw.getvalue().decode(encoding)
    assert json.loads(output) == data
    if encoding == "utf-8":
        assert "资料" in output
    else:
        assert "\\u8d44\\u6599" in output
