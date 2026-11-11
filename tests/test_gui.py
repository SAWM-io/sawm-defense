"""Real native-widget smoke tests, isolated from service worker threads.

Tcl/Tk must be finalized on its creating thread. A dedicated subprocess prevents
later GC in an unrelated pytest worker from destroying a retired Tcl interpreter.
"""
import copy
import gc
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

tk = pytest.importorskip("tkinter")
from sawm_defense.gui import DefenseApp, _lines


STATE = {
    "running": False,
    "settings": {"monitor_paths": [], "poll_seconds": 5, "automatic_actions": []},
    "snapshot": {
        "sampled_at": "2026-11-11T12:00:00+00:00", "cpu_percent": 13.2,
        "memory_percent": 47.1, "processes": [], "connections": [],
        "capabilities": [{"name": "Réseau", "available": False, "reason": "Permission refusée"}],
        "coverage": {"files_seen": 0},
    },
    "events": [{"id": "event-demo", "timestamp": "2026-11-11T12:00:00+00:00", "kind": "file_modified", "severity": "warning", "summary": "Fichier modifié", "details": {"path": "/tmp/example"}}],
    "actions": [], "calls": [], "journal": {"valid": True},
    "antivirus": {"available": False, "engine": None},
    "cloud": {"configured": False, "enabled": False}, "key": {"available": False},
}


class FakeService:
    def __init__(self, state_dir=None):
        self.constructed_on = threading.get_ident()
        self.status_threads = []
        self.actions = []
        self.closed = False

    def status(self):
        self.status_threads.append(threading.get_ident())
        return copy.deepcopy(STATE)

    def act(self, *args, **kwargs):
        self.actions.append((args, kwargs))
        return {"status": "denied"}

    def close(self):
        self.closed = True


def spin(root, predicate, timeout=3):
    stop = time.monotonic() + timeout
    while time.monotonic() < stop:
        root.update()
        if predicate():
            return
        time.sleep(.01)
    assert predicate(), "UI worker did not finish before the test deadline"


def _native_smoke():
    try:
        root = tk.Tk()
    except tk.TclError as error:
        return {"skip": f"No native display: {error}"}
    root.withdraw()
    app = DefenseApp(root, service_factory=FakeService)
    try:
        spin(root, lambda: app._settings_loaded)
        assert app.service.constructed_on != threading.get_ident()
        assert app.service.status_threads
        assert all(ident != threading.get_ident() for ident in app.service.status_threads)
        assert app.cards["av"][0].cget("text") == "Absent"
        assert "Permission refusée" in app.coverage_text.get("1.0", "end")
        assert len(app.tabs.tabs()) == 6
        assert len(app._history) == 1
        app._apply_status(copy.deepcopy(STATE))
        assert len(app._history) == 1
        next_state = copy.deepcopy(STATE)
        next_state["snapshot"]["sampled_at"] = "2026-11-11T12:00:05+00:00"
        next_state["snapshot"]["cpu_percent"] = 26.4
        app._apply_status(next_state)
        assert list(app._history) == [(13.2, 47.1), (26.4, 47.1)]
        app.event_tree.selection_set("event-demo")
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("sawm_defense.gui.messagebox.askokcancel", lambda *args, **kwargs: False)
            app._act()
        assert app.service.actions == []
        return {"threading": True, "truthful_status": True, "graph": True, "confirmation": True}
    finally:
        app._closing = True
        for timer in root.tk.splitlist(root.tk.call("after", "info")):
            root.after_cancel(timer)
        if app.service:
            app.service.close()
        # Dispose variables while their Tcl interpreter still exists and while
        # this is the main thread, before discarding widget callback cycles.
        app._vars.clear()
        app.auto_vars.clear()
        app.event_filter = None
        app.manual_action = None
        root.destroy()
        del app
        del root
        gc.collect()


@pytest.fixture(scope="module")
def native_result():
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve())],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    if result.get("skip"):
        pytest.skip(result["skip"])
    return result


def test_gui_constructs_and_reads_service_off_main_thread(native_result):
    assert native_result["threading"] and native_result["truthful_status"]


def test_same_measurement_not_repeated_in_graph(native_result):
    assert native_result["graph"]


def test_cancelling_manual_confirmation_never_calls_executor(native_result):
    assert native_result["confirmation"]


def test_scope_lines_are_distinct_and_ordered():
    assert _lines(" /tmp/a\n\n/tmp/b\n/tmp/a ") == ["/tmp/a", "/tmp/b"]


if __name__ == "__main__":
    print(json.dumps(_native_smoke()))
