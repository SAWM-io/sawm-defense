"""Prove that the frozen application creates a visible window for its own PID.

Disposable offline profile. No clicks, credentials, privileged actions or claims
about business workflows. Linux needs Xvfb, xdotool and x11-utils; other probes
use native APIs without accessibility permissions. Linux also requires libxres1
for server-side PID attribution without an optional _NET_WM_PID property.
Total budget: 20 seconds.
"""
import argparse
from contextlib import closing
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time


def linux_owner_pid(identifier):
    """Attribute an X resource using XRes 1.2, not a client-set window tag.

    Tk 8.6 only writes _NET_WM_PID when WM_CLIENT_MACHINE was configured.
    XRes uses the local X client's actual PID and works without a window manager.
    """
    class ClientSpec(ctypes.Structure):
        _fields_ = [("client", ctypes.c_ulong), ("mask", ctypes.c_ulong)]

    class ClientValue(ctypes.Structure):
        _fields_ = [("spec", ClientSpec), ("length", ctypes.c_long), ("value", ctypes.c_void_p)]

    x11_name, xres_name = ctypes.util.find_library("X11"), ctypes.util.find_library("XRes")
    if not x11_name or not xres_name:
        raise RuntimeError("XRes PID attribution unavailable; install libxres1 on the Linux runner")
    x11, xres = ctypes.CDLL(x11_name), ctypes.CDLL(xres_name)
    x11.XOpenDisplay.argtypes, x11.XOpenDisplay.restype = [ctypes.c_char_p], ctypes.c_void_p
    x11.XCloseDisplay.argtypes, x11.XCloseDisplay.restype = [ctypes.c_void_p], ctypes.c_int
    int_pointer = ctypes.POINTER(ctypes.c_int)
    for name in ("XResQueryExtension", "XResQueryVersion"):
        getattr(xres, name).argtypes = [ctypes.c_void_p, int_pointer, int_pointer]
        getattr(xres, name).restype = ctypes.c_int
    value_pointer = ctypes.POINTER(ClientValue)
    xres.XResQueryClientIds.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.POINTER(ClientSpec),
                                       ctypes.POINTER(ctypes.c_long), ctypes.POINTER(value_pointer)]
    xres.XResQueryClientIds.restype = ctypes.c_int
    xres.XResGetClientPid.argtypes, xres.XResGetClientPid.restype = [value_pointer], ctypes.c_int
    xres.XResClientIdsDestroy.argtypes, xres.XResClientIdsDestroy.restype = [ctypes.c_long, value_pointer], None
    display = x11.XOpenDisplay(None)
    if not display:
        raise RuntimeError("Cannot open the X display to verify window ownership")
    try:
        first, second = ctypes.c_int(), ctypes.c_int()
        if not xres.XResQueryExtension(display, ctypes.byref(first), ctypes.byref(second)):
            raise RuntimeError("X server does not expose the X-Resource extension")
        if (not xres.XResQueryVersion(display, ctypes.byref(first), ctypes.byref(second))
                or (first.value, second.value) < (1, 2)):
            raise RuntimeError("X-Resource 1.2 is required for native client PID attribution")
        spec, count, values = ClientSpec(int(identifier), 2), ctypes.c_long(), value_pointer()
        status = xres.XResQueryClientIds(display, 1, ctypes.byref(spec), ctypes.byref(count), ctypes.byref(values))
        try:
            # This particular XRes API returns X11 Success (0), unlike
            # XResQueryVersion. Missing PID is not a permissive fallback.
            if status != 0 or not values or not 0 < count.value <= 32:
                return None
            pids = {xres.XResGetClientPid(ctypes.byref(values[index])) for index in range(count.value)}
            pids.discard(-1)
            return next(iter(pids)) if len(pids) == 1 else None
        finally:
            if values:
                xres.XResClientIdsDestroy(count, values)
    finally:
        x11.XCloseDisplay(display)


def linux_window(pid):
    if not os.environ.get("DISPLAY"):
        raise RuntimeError("No X display; run this probe with xvfb-run")
    if not shutil.which("xdotool") or not shutil.which("xwininfo"):
        raise RuntimeError("Install xdotool and x11-utils on the Linux test runner")
    probe_deadline = time.monotonic() + 1
    try:
        # Name is only a candidate filter. XRes must then establish the exact
        # owner PID; a same-named window belonging to another process fails.
        found = subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "^SAWM Defense.*Protection"],
                               capture_output=True, text=True, timeout=.5)
    except subprocess.TimeoutExpired:
        return None
    for identifier in found.stdout.splitlines()[:32]:
        remaining = probe_deadline - time.monotonic()
        if remaining <= 0:
            break
        if not identifier.isdecimal():
            continue
        owner = linux_owner_pid(identifier)
        if owner != pid:
            continue
        try:
            info = subprocess.run(["xwininfo", "-id", identifier, "-stats"], capture_output=True,
                                  text=True, timeout=min(.5, remaining), env={**os.environ, "LC_ALL": "C"})
        except subprocess.TimeoutExpired:
            continue
        width = re.search(r"^\s*Width:\s*(\d+)", info.stdout, re.M)
        height = re.search(r"^\s*Height:\s*(\d+)", info.stdout, re.M)
        if (info.returncode == 0 and "Map State: IsViewable" in info.stdout
                and "SAWM Defense" in info.stdout and "Protection" in info.stdout and width and height
                and int(width[1]) >= 800 and int(height[1]) >= 500):
            return {"window_id": identifier, "owner_pid": owner, "width": int(width[1]), "height": int(height[1]),
                    "method": "XRes 1.2 server-side owner PID + xwininfo IsViewable + application title"}
    return None


def windows_window(pid):
    from ctypes import wintypes
    user = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user.EnumWindows.restype = wintypes.BOOL
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowThreadProcessId.restype = wintypes.DWORD
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.IsWindowVisible.restype = wintypes.BOOL
    user.IsIconic.argtypes = [wintypes.HWND]
    user.IsIconic.restype = wintypes.BOOL
    user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user.GetWindowRect.restype = wintypes.BOOL
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.GetWindowTextW.restype = ctypes.c_int
    result = []

    @callback_type
    def inspect(hwnd, _):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid or not user.IsWindowVisible(hwnd) or user.IsIconic(hwnd):
            return True
        title = ctypes.create_unicode_buffer(512)
        user.GetWindowTextW(hwnd, title, len(title))
        if not title.value.startswith("SAWM Defense") or "Protection" not in title.value:
            return True
        rect = wintypes.RECT()
        if user.GetWindowRect(hwnd, ctypes.byref(rect)):
            width, height = rect.right - rect.left, rect.bottom - rect.top
            if width >= 800 and height >= 500:
                result.append({"window_id": int(hwnd), "owner_pid": owner.value, "width": width, "height": height,
                               "method": "Win32 EnumWindows + owner PID + IsWindowVisible + GetWindowRect"})
        return True

    if not user.EnumWindows(inspect, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    return result[0] if result else None


def mac_window(pid):
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    cg = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
    pointer = ctypes.c_void_p
    for name, arguments, output in (
        ("CFArrayGetCount", [pointer], ctypes.c_long),
        ("CFArrayGetValueAtIndex", [pointer, ctypes.c_long], pointer),
        ("CFDictionaryGetValue", [pointer, pointer], pointer),
        ("CFStringCreateWithCString", [pointer, ctypes.c_char_p, ctypes.c_uint32], pointer),
        ("CFNumberGetValue", [pointer, ctypes.c_int, pointer], ctypes.c_bool),
        ("CFRelease", [pointer], None),
    ):
        function = getattr(cf, name)
        function.argtypes, function.restype = arguments, output
    cg.CGWindowListCopyWindowInfo.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    cg.CGWindowListCopyWindowInfo.restype = pointer

    def value(dictionary, key):
        native_key = cf.CFStringCreateWithCString(None, key.encode(), 0x08000100)
        try:
            return cf.CFDictionaryGetValue(dictionary, native_key)
        finally:
            cf.CFRelease(native_key)

    def number(dictionary, key):
        item = value(dictionary, key)
        output = ctypes.c_double()
        return output.value if item and cf.CFNumberGetValue(item, 6, ctypes.byref(output)) else None

    # On-screen windows only, excluding desktop elements. No screen recording,
    # title extraction, Apple Events or Accessibility permission requested.
    windows = cg.CGWindowListCopyWindowInfo(1 | 16, 0)
    if not windows:
        raise RuntimeError("CoreGraphics window list unavailable in this login session")
    try:
        for index in range(min(4096, cf.CFArrayGetCount(windows))):
            window = cf.CFArrayGetValueAtIndex(windows, index)
            if number(window, "kCGWindowOwnerPID") != pid or number(window, "kCGWindowLayer") != 0:
                continue
            bounds = value(window, "kCGWindowBounds")
            if not bounds:
                continue
            width, height = number(bounds, "Width"), number(bounds, "Height")
            if width is not None and height is not None and width >= 800 and height >= 500:
                return {"window_id": int(number(window, "kCGWindowNumber")), "owner_pid": pid,
                        "width": int(width), "height": int(height), "method": "CoreGraphics on-screen layer-0 window + owner PID"}
    finally:
        cf.CFRelease(windows)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    result = {"platform": platform.system(), "architecture": platform.machine(), "packaged_gui": True,
              "visible_window": False, "business_workflows_tested": False, "clicks_tested": False,
              "cloud_enabled": False, "upload_enabled": False, "protect_downloads": False,
              "notifications_enabled": False, "monitor_on_launch": False, "success": False}
    process = None
    try:
        probe = {"Linux": linux_window, "Windows": windows_window, "Darwin": mac_window}[platform.system()]
        binary = args.binary.resolve(strict=True)
        with binary.open("rb") as stream:
            result["binary_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        with tempfile.TemporaryDirectory(prefix="sawm-gui-bundle-proof-") as temporary:
            work = Path(temporary).resolve()
            state = work / "state"
            state.mkdir(mode=0o700)
            config = {"cloud_enabled": False, "cloud_upload_enabled": False, "cloud_per_hour": 0,
                      "space_id": "", "entity_id": "", "monitor_paths": [], "automatic_actions": [],
                      "monitor_on_launch": False, "notifications_enabled": False, "protect_downloads": False,
                      "automatic_scan_enabled": False, "autonomous_analysis_enabled": False,
                      "auth_journal_enabled": False, "auth_log_paths": [], "autoblock_auth_ips": False}
            config_path = state / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            config_path.chmod(0o600)
            with (work / "stdout.txt").open("wb") as stdout, (work / "stderr.txt").open("wb") as stderr:
                try:
                    process = subprocess.Popen([str(binary), "--state-dir", str(state), "gui"],
                                               stdout=stdout, stderr=stderr, cwd=work)
                    result["pid"] = process.pid
                    # Reserve up to six seconds for bounded cleanup.
                    deadline = started + 14
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            raise RuntimeError("GUI exited before a visible owned window was verified")
                        window = probe(process.pid)
                        if window:
                            result.update({"visible_window": True, "window": window})
                            # Verify the window persists, not only a transient
                            # splash or a process which immediately crashes.
                            time.sleep(.5)
                            if process.poll() is not None or not probe(process.pid):
                                raise RuntimeError("Owned window did not remain visible")
                            result["success"] = True
                            break
                        time.sleep(.2)
                    if not result["visible_window"]:
                        raise RuntimeError("No visible window for the packaged process within the time budget")
                finally:
                    if process is not None:
                        if process.poll() is None:
                            process.terminate()
                            result["cleanup"] = "TerminateProcess" if os.name == "nt" else "SIGTERM"
                            try:
                                process.wait(timeout=max(.1, min(3, started + 18 - time.monotonic())))
                            except subprocess.TimeoutExpired:
                                process.kill()
                                result["cleanup"] += ", then process.kill"
                                process.wait(timeout=max(.1, started + 20 - time.monotonic()))
                        else:
                            result["cleanup"] = "process already exited"
                        result["exit_code"] = process.returncode
                        result["test_process_reaped"] = process.poll() is not None
            database = state / "evidence.sqlite3"
            if not database.exists():
                raise RuntimeError("Disposable profile journal absent; cannot verify zero Cloud calls")
            # sqlite3's own context manager commits/rolls back but does not
            # close the file; explicit closing is required before Windows cleanup.
            with closing(sqlite3.connect(str(database), timeout=1)) as db:
                result["cloud_calls_recorded"] = db.execute("SELECT COUNT(*) FROM ledger WHERE kind='call'").fetchone()[0]
            if result["cloud_calls_recorded"]:
                result["success"] = False
                result["error"] = "Unexpected Cloud call recorded in offline GUI profile"
            result["stderr_bytes"] = (work / "stderr.txt").stat().st_size
    except Exception as error:
        result["success"] = False
        result["error"] = type(error).__name__ + ": " + str(error)[:400]
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    result["notes"] = "Native visible-window smoke test only. Offline disposable profile. Cleanup is process termination, not a simulated user click."
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
