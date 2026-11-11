"""Structured CLI output remains usable with redirected legacy OS encodings."""
import io
import json

import pytest

from sawm_defense.cli import emit


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
