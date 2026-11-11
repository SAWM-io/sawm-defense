#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if ! command -v python3 >/dev/null 2>&1; then
  echo 'Installer Python 3.12+, python3-venv et python3-tk depuis votre distribution.' >&2
  exit 1
fi
python3 -c 'import sys, tkinter, venv; assert sys.version_info >= (3,12)' || {
  echo 'Dépendances manquantes. Ubuntu 24.04 : sudo apt install python3 python3-venv python3-tk' >&2
  exit 1
}
exec python3 "$ROOT/packaging/install.py" "$@"
