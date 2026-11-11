"""Only inert fixtures are inspected; native executables are mocked throughout."""
import hashlib
import json
from pathlib import Path
import plistlib
import struct
from types import SimpleNamespace
import zipfile

import pytest

import sawm_defense.file_inspection as inspector


@pytest.fixture(autouse=True)
def no_host_native_tools(monkeypatch):
    monkeypatch.setattr(inspector.platform, "system", lambda: "Linux")
    monkeypatch.setattr(inspector.subprocess, "run", lambda *a, **kw: pytest.fail("unmocked native tool"))


def codes(result):
    return {f["code"] for f in result["findings"]}


def test_text_read_only_hash_and_no_claim_of_safety(tmp_path):
    target = tmp_path / "ordinary.txt"
    original = b"Ordinary project note.\n"
    target.write_bytes(original)
    result = inspector.inspect_file(target)
    assert result["status"] == "no_indicator"
    assert result["sha256"] == hashlib.sha256(original).hexdigest()
    assert result["actual_type"] == "text"
    assert not result["signature"]["trusted_program"]
    assert result["limitations"]
    assert target.read_bytes() == original


def test_executable_disguised_as_document_is_indicator_not_malware(tmp_path):
    target = tmp_path / "invoice.pdf"
    target.write_bytes(b"#! /bin/sh\necho NEVER_EXECUTE\n")
    result = inspector.inspect_file(target)
    assert result["status"] == "suspicious"
    assert "extension_type_mismatch" in codes(result)
    assert all(f["malware_proven"] is False for f in result["findings"])


def test_double_extension_is_explicitly_not_proof(tmp_path):
    target = tmp_path / "invoice.pdf.exe"
    target.write_text("text only")
    result = inspector.inspect_file(target)
    assert "double_extension" in codes(result)
    assert not result["findings"][0]["malware_proven"]


def test_pdf_active_content_is_static_and_bounded(tmp_path):
    target = tmp_path / "document.pdf"
    target.write_bytes(b"%PDF-1.7\n/OpenAction << /S /JavaScript /JS (app.alert('test')) >>\n")
    result = inspector.inspect_file(target)
    assert result["status"] == "suspicious"
    assert "pdf_active_content" in codes(result)
    assert "/JavaScript" in result["metadata"]["pdf_markers"]
    assert any("pas interprété" in note for note in result["limitations"])


def test_zip_traversal_and_macros_do_not_extract(tmp_path):
    target = tmp_path / "input.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("../outside.txt", "test")
        archive.writestr("C:\\outside.txt", "test")
        archive.writestr("word/vbaProject.bin", "inert fixture")
    result = inspector.inspect_file(target)
    assert result["status"] == "suspicious"
    assert {"archive_path_traversal", "office_active_content"} <= codes(result)
    assert result["metadata"]["archive"]["entries"] == 3
    assert not (tmp_path / "outside.txt").exists()
    assert not (tmp_path / "word").exists()


def test_archive_expansion_checked_from_metadata_only(tmp_path):
    target = tmp_path / "compressed.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", b"0" * (11 * 1024 * 1024))
    result = inspector.inspect_file(target)
    assert "archive_expansion_risk" in codes(result)
    assert result["metadata"]["archive"]["expanded_bytes"] == 11*1024*1024
    assert not (tmp_path / "large.txt").exists()


def test_archive_metadata_limit_rejects_before_zip_parser(tmp_path, monkeypatch):
    target = tmp_path / "bounded.zip"
    target.write_bytes(struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1001, 1001, 0, 0, 0))
    monkeypatch.setattr(inspector.zipfile, "ZipFile", lambda *a, **kw: pytest.fail("oversized directory parsed"))
    result = inspector.inspect_file(target)
    assert result["metadata"]["archive"]["directory_inspected"] is False
    assert any("limite sûre" in note for note in result["limitations"])


def test_eicar_test_is_never_described_as_real_malware(tmp_path):
    target = tmp_path / "test.txt"
    target.write_bytes(inspector._EICAR)
    result = inspector.inspect_file(target)
    assert result["status"] == "suspicious"
    finding = next(f for f in result["findings"] if f["code"] == "antivirus_test_file")
    assert finding["test_fixture"] is True
    assert finding["malware_proven"] is False
    assert "TEST" in finding["summary"]


@pytest.mark.parametrize("parent_link", [False, True])
def test_symlink_paths_not_read(tmp_path, parent_link):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("must not inspect through link")
    target = tmp_path / "link"
    try: target.symlink_to(source if parent_link else source / "file.txt", target_is_directory=parent_link)
    except OSError: pytest.skip("symlink creation unavailable")
    result = inspector.inspect_file(target / "file.txt" if parent_link else target)
    assert result["status"] == "error"
    assert result["sha256"] is None


def test_size_budget_and_bad_limit(tmp_path):
    target = tmp_path / "large.bin"
    with target.open("wb") as out:
        out.truncate(2*1024*1024)
    assert inspector.inspect_file(target, max_file_mb=1)["status"] == "error"
    assert inspector.inspect_file(target, max_file_mb=True)["status"] == "error"


def test_changed_file_refuses_completed_inspection(tmp_path, monkeypatch):
    target = tmp_path / "text.txt"
    target.write_text("before")
    original = inspector.file_digest
    calls = []
    def changing(path, limit):
        calls.append(1)
        if len(calls) == 2: target.write_text("after")
        return original(path, limit)
    monkeypatch.setattr(inspector, "file_digest", changing)
    result = inspector.inspect_file(target)
    assert result["status"] == "error"


def test_replacement_after_hash_is_rejected_before_prefix(tmp_path, monkeypatch):
    target = tmp_path / "text.txt"
    target.write_text("before")
    original = inspector.file_digest
    def replace(path, limit):
        digest, st = original(path, limit)
        other = tmp_path / "replacement"
        other.write_text("after")
        other.replace(target)
        return digest, st
    monkeypatch.setattr(inspector, "file_digest", replace)
    result = inspector.inspect_file(target)
    assert result["status"] == "error"
    assert result["actual_type"] == "unknown"


def test_mac_signature_fixed_arguments_and_no_execution(tmp_path, monkeypatch):
    target = tmp_path / '$(touch attack);file'
    target.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00"*28)
    seen = []
    monkeypatch.setattr(inspector.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(inspector.shutil, "which", lambda name: "/usr/bin/"+name)
    def run(argv, **kw):
        seen.append((argv, kw))
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(inspector.subprocess, "run", run)
    result = inspector.inspect_file(target)
    assert result["signature"]["status"] == "valid"
    assert result["signature"]["trusted_program"] is False
    assert seen[0][0] == ["/usr/bin/codesign", "--verify", "--strict", "--", str(target)]
    assert seen[0][1]["shell"] is False
    assert not (tmp_path / "attack").exists()


def test_windows_signature_path_not_code_and_unsigned_not_malware(tmp_path, monkeypatch):
    target = tmp_path / "x';Write-Host-danger.ps1"
    target.write_text("Write-Host 'Hello'")
    seen = []
    monkeypatch.setattr(inspector.platform, "system", lambda: "Windows")
    monkeypatch.setattr(inspector.shutil, "which", lambda name: "powershell.exe")
    def run(argv, **kw):
        seen.append((argv, kw))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"status":"NotSigned", "signer":""}), stderr="")
    monkeypatch.setattr(inspector.subprocess, "run", run)
    result = inspector.inspect_file(target)
    assert result["signature"]["status"] == "unsigned"
    assert result["status"] == "no_indicator"
    assert str(target) not in seen[0][0][-1]
    assert seen[0][1]["env"]["SAWM_INSPECTION_PATH"] == str(target)
    assert seen[0][1]["shell"] is False


def test_download_origin_omits_credentials_query_and_fragment(tmp_path, monkeypatch):
    target = tmp_path / "notes.txt"
    target.write_text("notes")
    def xattr(path, name, **kw):
        if name == "com.apple.quarantine": return b"0081;test"
        return plistlib.dumps(["https://name:password@example.org/download?token=secret#secret"])
    monkeypatch.setattr(inspector.os, "getxattr", xattr, raising=False)
    result = inspector.inspect_file(target)
    provenance = result["metadata"]["provenance"]
    assert provenance["download_marker"] is True
    assert provenance["download_origins"] == ["https://example.org/download"]
    assert "secret" not in json.dumps(result)


def test_java_header_not_confused_with_fat_macho(tmp_path):
    target = tmp_path / "Example.class"
    target.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d\x00\x0f\x0a\x00")
    result = inspector.inspect_file(target)
    assert result["actual_type"] != "Mach-O"


def test_writable_executable_elf_segment_is_reported(tmp_path):
    ident = b"\x7fELF\x02\x01\x01" + b"\x00"*9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 3, 0, 0, 0, 0, 0, 4096)
    target = tmp_path / "program"
    target.write_bytes(header + segment)
    result = inspector.inspect_file(target)
    assert result["actual_type"] == "ELF"
    assert "writable_executable_segment" in codes(result)
    assert not result["findings"][0]["malware_proven"]
