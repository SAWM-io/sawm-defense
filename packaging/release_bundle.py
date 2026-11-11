"""Package an already verified native build, without credentials or source engines.

Run on each target OS after build.py and verify_bundle.py. This does not cross
compile, sign with a publisher certificate, notarize, or publish a GitHub release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = {"Linux": "linux", "Windows": "windows", "Darwin": "macos"}
ARCHITECTURES = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}


def _native_target():
    try:
        return PLATFORMS[platform.system()], ARCHITECTURES[platform.machine().lower()]
    except KeyError as error:
        raise ValueError("Unsupported native OS or architecture") from error


def _safe_tree(source: Path):
    """Keep only ordinary build files and internal relative symlinks.

    PyInstaller's macOS bundle depends on symlinks; following them or rewriting
    them can invalidate its ad-hoc signature. Links outside the build are refused.
    """
    root = source.resolve(strict=True)
    for directory, dirs, files in os.walk(source, followlinks=False):
        for name in dirs + files:
            item = Path(directory) / name
            if item.is_symlink():
                if os.path.isabs(os.readlink(item)) or not item.resolve(strict=True).is_relative_to(root):
                    raise ValueError("The build contains an external or absolute symlink")
            elif not item.is_file() and not item.is_dir():
                raise ValueError("The build contains a non-ordinary file")


_REQUIRED_CHECKS = (
    "packaged_cli", "file_change_detected", "manual_quarantine_verified", "restore_verified",
    "deletion_detected", "journal_verified", "report_exported", "report_content_verified",
    "automatic_file_inspection", "persistent_alert", "mission_submitted_and_executed_by_daemon",
    "suspicion_did_not_quarantine_without_proof", "offline_configuration_verified",
    "disposable_scope_verified", "order_receipt_verified", "binary_unchanged",
)


def _proof(path: Path, version: str, target: str, architecture: str, *, binary: Path):
    if path.stat().st_size > 128 * 1024:
        raise ValueError("Validation proof exceeds the allowed size")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or type(data.get("proof_schema")) is not int or data["proof_schema"] != 2:
        raise ValueError("A complete current validation proof is required")
    if data.get("validation_status") != "passed" or any(data.get(field) is not True for field in _REQUIRED_CHECKS):
        raise ValueError("Validation proof contains missing or failed checks")
    if data.get("binary_version") != version or not isinstance(data.get("platform"), str) or data.get("platform") not in PLATFORMS or PLATFORMS[data["platform"]] != target:
        raise ValueError("Validation proof belongs to a different version or OS")
    if data.get("binary_version_source") != "executable --version":
        raise ValueError("Version must have been read from the executable")
    if ARCHITECTURES.get(str(data.get("architecture", "")).lower()) != architecture:
        raise ValueError("Validation proof belongs to a different architecture")
    for field in ("bounded_watch_exit_code", "cloud_calls"):
        if type(data.get(field)) is not int or data[field] != 0:
            raise ValueError("Validation has a nonzero exit or Cloud call count")
    if data.get("cloud_enabled") is not False or data.get("native_notification_delivery") != "disabled":
        raise ValueError("Validation did not preserve the offline test configuration")
    for field, minimum in (("events_recorded", 3), ("actions_recorded", 2), ("journal_entries_verified", 5)):
        if type(data.get(field)) is not int or data[field] < minimum:
            raise ValueError("Validation did not record the required evidence")
    if data["journal_entries_verified"] < data["events_recorded"] + data["actions_recorded"]:
        raise ValueError("Journal verification does not cover the reported evidence")
    if data.get("download_type_detected") != "script" or not isinstance(data.get("static_findings"), list) or "extension_type_mismatch" not in data["static_findings"]:
        raise ValueError("Validation lacks the expected static inspection evidence")
    with binary.open("rb") as stream:
        actual_digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if data.get("binary_sha256") != actual_digest:
        raise ValueError("Validation proof belongs to a different executable")
    return data


def create_archive(dist: Path, output: Path, *, version: str, proof: Path | None = None):
    target, architecture = _native_target()
    if re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version) is None:
        raise ValueError("Invalid release version")
    source = dist / ("SAWM Defense.app" if target == "macos" else "sawm-defense")
    binary = source / ("Contents/MacOS/SAWM Defense" if target == "macos" else "sawm-defense.exe" if target == "windows" else "sawm-defense")
    if not binary.is_file() or binary.is_symlink():
        raise ValueError("The expected native executable is missing")
    _safe_tree(source)
    _safe_tree(ROOT / "docs")
    if proof is None:
        raise ValueError("A complete packaged validation proof is required before archiving")
    validation = _proof(proof, version, target, architecture, binary=binary)
    output.mkdir(parents=True, exist_ok=True)
    stem = f"SAWM-Defense-{version}-{target}-{architecture}"
    archive = output / (stem + (".tar.gz" if target == "linux" else ".zip"))
    if archive.exists():
        raise FileExistsError(f"Archive already exists: {archive.name}")
    with tempfile.TemporaryDirectory(prefix="sawm-release-") as work:
        package = Path(work) / stem
        package.mkdir()
        shutil.copytree(source, package / source.name, symlinks=True)
        for filename in ("LICENSE", "NOTICE"):
            shutil.copy2(ROOT / filename, package / filename)
        shutil.copytree(ROOT / "docs", package / "docs", symlinks=True)
        if validation:
            (package / "PACKAGED-VALIDATION.json").write_text(json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        launch = {
            "windows": 'Open sawm-defense/sawm-defense.exe for the desktop app. In PowerShell: .\\sawm-defense\\sawm-defense.exe --help',
            "linux": 'Desktop: ./sawm-defense/sawm-defense. CLI: ./sawm-defense/sawm-defense --help. A graphical desktop and native Tk libraries are required for the GUI.',
            "macos": 'Copy SAWM Defense.app to Applications, then open it. CLI: "/Applications/SAWM Defense.app/Contents/MacOS/SAWM Defense" --help',
        }[target]
        (package / "START-HERE.txt").write_text(
            f"SAWM Defense {version} | {target} {architecture}\n\n{launch}\n\n"
            "Keep the application folder intact: its bundled libraries are required.\n"
            "Configure your own Basira / SAWM Cloud API credentials inside the app.\n"
            "Monitoring scope and automatic actions must be explicitly configured.\n"
            "No system-wide administrator permission or kernel driver is installed by this archive.\n\n"
            "This pilot release is not publisher-signed or Apple-notarized. The macOS build may carry an ad-hoc signature.\n"
            "OS security checks may require review before launch; do not disable system protections globally.\n"
            "Read docs/CLI.md, docs/INTERFACE.md, docs/KERNEL.md and docs/VALIDATION.md for capabilities and limits.\n"
            "ISO / CIS mappings support assessment; they do not certify this application or your organization.\n",
            encoding="utf-8",
        )
        try:
            if target == "macos":
                # Apple's archiver preserves the app's symlinks, permissions and resources.
                subprocess.run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(package), str(archive.resolve())], check=True, timeout=300)
            elif target == "linux":
                with tarfile.open(archive, "w:gz", dereference=False) as out:
                    out.add(package, arcname=stem)
            else:
                # Native Windows builds have no required app-bundle symlinks.
                with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as out:
                    for item in sorted(package.rglob("*")):
                        if item.is_symlink():
                            raise ValueError("Windows portable builds must not contain symlinks")
                        if item.is_file():
                            out.write(item, item.relative_to(package.parent).as_posix())
        except Exception:
            archive.unlink(missing_ok=True)
            raise
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    (output / (archive.name + ".sha256")).write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    manifest = {"version": version, "platform": target, "architecture": architecture, "archive": archive.name,
                "size_bytes": archive.stat().st_size, "sha256": digest, "publisher_signed": False,
                "apple_notarized": False, "packaged_validation_included": validation is not None,
                "distribution": "portable native pilot; no private SAWM/Basira/TSST/ODVL engine included"}
    (output / (stem + ".json")).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if validation:
        (output / (stem + "-validation.json")).write_text(json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "release")
    parser.add_argument("--proof", type=Path, required=True, help="JSON generated by verify_bundle.py for this exact platform/version")
    args = parser.parse_args()
    with (ROOT / "pyproject.toml").open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    result = create_archive(args.dist, args.output_dir, version=version, proof=args.proof)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
