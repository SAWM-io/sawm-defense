"""Build on each target OS; PyInstaller is deliberately not a cross compiler."""
from pathlib import Path
import platform
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
name = "SAWM Defense" if sys.platform == "darwin" else "sawm-defense"
args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", name,
        "--paths", str(root), "--collect-submodules", "keyring.backends", "--collect-data", "certifi", "--collect-data", "sawm_defense",
        "--exclude-module", "pytest", "--exclude-module", "numpy", "--exclude-module", "matplotlib",
        "--add-data", str(root / "docs") + ":docs",
        "--add-data", str(root / "LICENSE") + ":.",
        "--add-data", str(root / "NOTICE") + ":."]
if sys.platform == "darwin":
    args += ["--windowed", "--osx-bundle-identifier", "io.sawm.defense",
             "--icon", str(root / "sawm_defense/assets/sawm-defense.icns")]
elif sys.platform == "win32":
    args += ["--icon", str(root / "sawm_defense/assets/sawm-defense.ico")]
args += [str(root / "packaging/entrypoint.py")]
subprocess.run(args, cwd=root, check=True)
print("Built", platform.system(), platform.machine(), root / "dist")
