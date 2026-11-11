"""Bounded static inspection. Indicators are evidence to investigate, not malware verdicts.

Nothing is executed or extracted. Signature verification, when available, uses
fixed native commands and an argument/environment value for the selected path.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from contextlib import contextmanager
import platform
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import json
from urllib.parse import urlsplit, urlunsplit
import zipfile

from .platforms import file_digest, no_symlink


_PREFIX_BYTES = 131072
_MAX_ZIP_ENTRIES = 1000
_MAX_CENTRAL_BYTES = 2 * 1024 * 1024
# This is the published, harmless antivirus test string, not a malware signature.
_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_WINDOWS_SIGNATURE = r'''$ErrorActionPreference='Stop'
try {
  $s=Get-AuthenticodeSignature -LiteralPath $env:SAWM_INSPECTION_PATH
  [pscustomobject]@{status=$s.Status.ToString(); signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}} | ConvertTo-Json -Compress
} catch { exit 1 }
'''


def _finding(code, summary, level="warning"):
    return {"code": code, "level": level, "summary": summary, "malware_proven": False}


def _format(prefix):
    if prefix.startswith(b"\x7fELF"):
        return "ELF"
    if prefix.startswith(b"MZ"):
        return "PE/DOS"
    if prefix[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    # CAFEBABE is also the Java-class magic; FAT Mach-O needs an architecture count.
    if prefix[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca") and len(prefix) >= 12:
        endian = ">" if prefix[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "<"
        count, cpu = struct.unpack_from(endian + "II", prefix, 4)
        if 1 <= count <= 64 and cpu in {7, 12, 18, 0x01000007, 0x0100000c}:
            return "Mach-O"
    if prefix.startswith(b"%PDF-"):
        return "PDF"
    if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP"
    if prefix.startswith(b"#!"):
        return "script"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if prefix.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    if prefix and b"\x00" not in prefix:
        try:
            prefix.decode("utf-8")
            return "text"
        except UnicodeDecodeError:
            pass
    return "unknown"


def _provenance(path):
    out = {"owner_uid": None, "download_marker": False, "download_origins": []}
    if not hasattr(os, "getxattr"):
        return out
    try:
        marker = os.getxattr(path, "com.apple.quarantine", follow_symlinks=False)
        out["download_marker"] = bool(marker)
    except (OSError, TypeError):
        pass
    try:
        raw = os.getxattr(path, "com.apple.metadata:kMDItemWhereFroms", follow_symlinks=False)
        if len(raw) <= 8192:
            values = plistlib.loads(raw)
            if isinstance(values, list):
                for value in values[:5]:
                    if not isinstance(value, str):
                        continue
                    parsed = urlsplit(value)
                    if parsed.scheme in {"http", "https"} and parsed.hostname:
                        # Query, fragment and userinfo may contain credentials.
                        origin = urlunsplit((parsed.scheme, parsed.hostname, parsed.path[:256], "", ""))
                        out["download_origins"].append(origin)
    except (OSError, TypeError, ValueError, plistlib.InvalidFileException):
        pass
    return out


def _signature(path, actual_type):
    system = platform.system()
    base = {"status": "not_checked", "trusted_program": False,
            "note": "Une signature valide n'établit pas qu'un logiciel est sans danger."}
    if system == "Darwin" and actual_type == "Mach-O":
        tool = shutil.which("codesign")
        if tool is None:
            return {**base, "reason": "codesign indisponible"}
        try:
            result = subprocess.run([tool, "--verify", "--strict", "--", str(path)], shell=False,
                                    capture_output=True, text=True, timeout=5)
            return {**base, "status": "valid" if result.returncode == 0 else "not_verified", "engine": "codesign",
                    "reason": "Vérification native terminée ; un échec peut signifier une absence de signature."}
        except (OSError, subprocess.TimeoutExpired):
            return {**base, "status": "unavailable", "reason": "Vérification native indisponible ou délai dépassé"}
    if system == "Windows" and actual_type in {"PE/DOS", "script", "text"}:
        tool = shutil.which("powershell")
        if tool is None:
            return {**base, "reason": "PowerShell indisponible"}
        try:
            result = subprocess.run([tool, "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_SIGNATURE], shell=False,
                                    capture_output=True, text=True, timeout=5,
                                    env={**os.environ, "SAWM_INSPECTION_PATH": str(path)})
            if result.returncode or len(result.stdout) > 4096:
                raise ValueError("signature response unavailable")
            data = json.loads(result.stdout)
            mapping = {"Valid": "valid", "NotSigned": "unsigned", "HashMismatch": "hash_mismatch", "NotTrusted": "not_trusted",
                       "UnknownError": "not_verified", "NotSupportedFileFormat": "not_supported", "Incompatible": "not_supported"}
            if not isinstance(data, dict) or data.get("status") not in mapping:
                raise ValueError("signature response invalid")
            return {**base, "status": mapping[data["status"]], "engine": "Authenticode", "signer": str(data.get("signer", ""))[:512]}
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return {**base, "status": "unavailable", "reason": "Vérification Authenticode non exploitable"}
    return {**base, "reason": "Pas de vérificateur natif appliqué à ce format sur cet OS"}


def _binary(prefix, actual_type, findings, limitations):
    metadata = {}
    if actual_type == "ELF":
        try:
            bits, byte_order = prefix[4], prefix[5]
            if bits not in {1, 2} or byte_order not in {1, 2}:
                raise ValueError
            endian = "<" if byte_order == 1 else ">"
            header = struct.unpack_from(endian + ("16sHHIIIIIHHHHHH" if bits == 1 else "16sHHIQQQIHHHHHH"), prefix)
            metadata.update(bits=32 if bits == 1 else 64, machine=header[2])
            offset, entry_size, count = header[5], header[9], header[10]
            expected_size = 32 if bits == 1 else 56
            if count > 256 or entry_size < expected_size or offset + count*entry_size > len(prefix):
                limitations.append("En-têtes de segments ELF hors de la fenêtre d'inspection.")
            else:
                for n in range(count):
                    values = struct.unpack_from(endian + ("IIIIIIII" if bits == 1 else "IIQQQQQQ"), prefix, offset+n*entry_size)
                    flags = values[6] if bits == 1 else values[1]
                    if values[0] == 1 and flags & 3 == 3:
                        findings.append(_finding("writable_executable_segment", "Segment ELF à la fois exécutable et modifiable ; vérifier sa justification."))
                        break
        except (IndexError, struct.error, ValueError):
            findings.append(_finding("malformed_binary_header", "En-tête ELF incomplet ou non conforme."))
    if actual_type == "PE/DOS":
        try:
            offset = struct.unpack_from("<I", prefix, 0x3c)[0]
            if prefix[offset:offset+4] != b"PE\x00\x00":
                limitations.append("En-tête DOS reconnu, en-tête PE non confirmé dans la fenêtre lue.")
                return metadata
            machine, count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", prefix, offset+4)
            metadata.update(machine=machine, sections=count)
            start = offset+24+optional_size
            if count > 96 or start+count*40 > len(prefix):
                limitations.append("Table des sections PE hors de la fenêtre d'inspection.")
            else:
                for n in range(count):
                    flags = struct.unpack_from("<I", prefix, start+n*40+36)[0]
                    if flags & 0xa0000000 == 0xa0000000:
                        findings.append(_finding("writable_executable_segment", "Section PE à la fois exécutable et modifiable ; ce seul indice ne prouve pas un malware."))
                        break
        except (IndexError, struct.error, ValueError):
            findings.append(_finding("malformed_binary_header", "En-tête PE/DOS incomplet ou non conforme."))
    return metadata


def _zip(stream, size, findings, limitations):
    stream.seek(max(0, size-65557))
    end = stream.read(65557)
    offset = end.rfind(b"PK\x05\x06")
    if offset < 0 or offset+22 > len(end):
        findings.append(_finding("archive_directory_invalid", "Répertoire ZIP absent ou incomplet."))
        return {"directory_inspected": False}
    _, disk, central_disk, disk_count, count, central_size, central_offset, comment = struct.unpack_from("<4s4H2LH", end, offset)
    if disk or central_disk or disk_count != count or count == 65535 or central_size == 0xffffffff or central_offset == 0xffffffff:
        limitations.append("Archive multi-volume ou ZIP64 non inspectée.")
        return {"directory_inspected": False}
    if count > _MAX_ZIP_ENTRIES or central_size > _MAX_CENTRAL_BYTES or central_offset+central_size > size:
        limitations.append("Répertoire ZIP au-delà de la limite sûre ; aucune extraction effectuée.")
        return {"directory_inspected": False, "declared_entries": count}
    metadata = {"directory_inspected": True, "entries": 0, "compressed_bytes": 0, "expanded_bytes": 0}
    with zipfile.ZipFile(stream) as archive:
        names = set()
        for item in archive.infolist():
            metadata["entries"] += 1
            if metadata["entries"] > _MAX_ZIP_ENTRIES:
                limitations.append("Limite d'entrées atteinte.")
                break
            metadata["compressed_bytes"] += item.compress_size
            metadata["expanded_bytes"] += item.file_size
            name = item.filename.replace("\\", "/")
            if (name.startswith("/") or ".." in PurePosixPath(name).parts or re.match(r"^[A-Za-z]:", name)):
                findings.append(_finding("archive_path_traversal", "L'archive contient un chemin sortant du répertoire de destination ; ne pas extraire sans contrôle."))
            if name in names:
                findings.append(_finding("archive_duplicate_path", "Plusieurs entrées ZIP portent le même chemin."))
            names.add(name)
            if name.lower().endswith("vbaproject.bin"):
                findings.append(_finding("office_active_content", "Présence de macros Office ; leur contenu et leur intention ne sont pas déterminés.", "info"))
            if item.flag_bits & 1:
                limitations.append("Des entrées chiffrées ne peuvent pas être inspectées sans déchiffrement autorisé.")
            if item.file_size > 10*1024*1024 and item.file_size/max(1,item.compress_size) > 100:
                findings.append(_finding("archive_expansion_risk", "Ratio de décompression élevé ; risque de consommation excessive de ressources."))
        if metadata["expanded_bytes"] > 1024*1024*1024:
            findings.append(_finding("archive_expansion_risk", "Taille décompressée annoncée supérieure à 1 Gio ; aucune extraction effectuée."))
    return metadata


@contextmanager
def _open_same(path, expected):
    if not no_symlink(path):
        raise ValueError("Lien symbolique exclu")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or (current.st_ino, current.st_dev, current.st_size, current.st_mtime_ns) != (expected.st_ino, expected.st_dev, expected.st_size, expected.st_mtime_ns):
            raise ValueError("Le fichier a changé")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            yield stream
    finally:
        os.close(fd)


def inspect_file(path, max_file_mb=100):
    result = {"status": "error", "sha256": None, "actual_type": "unknown", "metadata": {}, "findings": [],
              "signature": {"status": "not_checked", "trusted_program": False},
              "limitations": ["Inspection statique bornée ; aucun fichier exécuté ni archive extraite.",
                              "L'absence d'indicateur ne prouve pas l'absence de malware."]}
    try:
        if type(max_file_mb) is not int or not 1 <= max_file_mb <= 2048:
            raise ValueError("Limite d'inspection invalide")
        target = Path(os.path.abspath(os.path.expanduser(path)))
        limit = max_file_mb*1024*1024
        before_sha, before = file_digest(target, limit)
        result["sha256"] = before_sha
        with _open_same(target, before) as stream:
            prefix = stream.read(_PREFIX_BYTES)
        actual = _format(prefix)
        findings, limitations = result["findings"], result["limitations"]
        result["actual_type"] = actual
        provenance = _provenance(target)
        provenance["owner_uid"] = getattr(before, "st_uid", None)
        result["metadata"] = {"size_bytes": before.st_size, "mode": stat.S_IMODE(before.st_mode),
                              "executable_bit": bool(before.st_mode & 0o111), "provenance": provenance,
                              "prefix_bytes_inspected": len(prefix)}
        suffixes = [x.lower() for x in target.suffixes]
        suffix = suffixes[-1] if suffixes else ""
        disguised = {".pdf", ".doc", ".docx", ".xlsx", ".jpg", ".png", ".txt", ".csv"}
        executable_extensions = {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh"}
        if len(suffixes) > 1 and suffixes[-2] in disguised and suffix in executable_extensions:
            findings.append(_finding("double_extension", "Double extension document/exécutable ; vérifier le type réel avant ouverture."))
        if actual in {"ELF", "PE/DOS", "Mach-O", "script"} and suffix in disguised:
            findings.append(_finding("extension_type_mismatch", "Le contenu exécutable ne correspond pas à l'extension de document affichée."))
        expected = {".pdf": {"PDF"}, ".png": {"PNG"}, ".jpg": {"JPEG"}, ".jpeg": {"JPEG"}, ".gif": {"GIF"},
                    ".zip": {"ZIP"}, ".docx": {"ZIP"}, ".xlsx": {"ZIP"}, ".pptx": {"ZIP"}}
        if suffix in expected and actual not in expected[suffix]:
            findings.append(_finding("format_mismatch", "La signature de format ne correspond pas à l'extension ; fichier incomplet ou trompeur possible."))
        result["metadata"].update(_binary(prefix, actual, findings, limitations))
        if actual == "PDF":
            active = [token.decode("ascii") for token in (b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/EmbeddedFile") if token in prefix]
            if active:
                findings.append(_finding("pdf_active_content", "Marqueurs d'actions ou de contenu embarqué PDF dans la fenêtre lue ; vérifier avant ouverture."))
                result["metadata"]["pdf_markers"] = active
            limitations.append("Le PDF n'est pas interprété ni décompressé ; les objets hors fenêtre ne sont pas inspectés.")
        if actual == "ZIP":
            with _open_same(target, before) as stream:
                result["metadata"]["archive"] = _zip(stream, before.st_size, findings, limitations)
        if prefix.strip() == _EICAR and before.st_size <= len(_EICAR)+4:
            findings.append({**_finding("antivirus_test_file", "Fichier de TEST EICAR reconnu : ce n'est pas un malware réel."), "test_fixture": True})
        result["signature"] = _signature(target, actual)
        if result["signature"].get("status") == "hash_mismatch":
            findings.append(_finding("signature_hash_mismatch", "La vérification native rapporte un contenu différent de celui signé."))
        after_sha, after = file_digest(target, limit)
        if before_sha != after_sha or (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns):
            raise ValueError("Le fichier a changé pendant l'inspection")
        # Deduplicate repeated archive findings without hiding categories.
        result["findings"] = list({f["code"]: f for f in findings}.values())
        result["limitations"] = list(dict.fromkeys(limitations))
        result["status"] = "suspicious" if any(f["level"] == "warning" for f in result["findings"]) else "no_indicator"
        return result
    except (OSError, ValueError, TypeError, struct.error, zipfile.BadZipFile, RuntimeError):
        return {**result, "status": "error", "reason": "Inspection non effectuée complètement : fichier illisible, lié, modifié, trop volumineux ou format invalide."}
