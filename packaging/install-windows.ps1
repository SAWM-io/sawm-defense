$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Python = Get-Command py -ErrorAction SilentlyContinue
if ($Python) {
    # Select the newest Python 3; install.py enforces the supported minimum.
    & py -3 "$Root\packaging\install.py" @args
} else {
    $Python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $Python) {
        throw 'Installez Python 3.12 avec Tcl/Tk depuis python.org, puis relancez. Aucun droit administrateur requis.'
    }
    & python "$Root\packaging\install.py" @args
}
if ($LASTEXITCODE -ne 0) { throw "Installation interrompue (code $LASTEXITCODE)." }
