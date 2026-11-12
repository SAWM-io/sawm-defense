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
    "settings": {"monitor_paths": [], "poll_seconds": 5, "automatic_actions": [], "notifications_enabled": True, "autonomous_analysis_enabled": True},
    "snapshot": {
        "sampled_at": "2026-11-11T12:00:00+00:00", "cpu_percent": 13.2,
        "memory_percent": 47.1, "processes": [], "connections": [],
        "capabilities": [{"name": "Réseau", "available": False, "reason": "Permission refusée"}],
        "coverage": {"files_seen": 0},
    },
    "events": [{"id": "event-demo", "timestamp": "2026-11-11T12:00:00+00:00", "kind": "file_modified", "severity": "warning", "summary": "Fichier modifié", "details": {"path": "/tmp/example"}}],
    "actions": [], "calls": [], "journal": {"valid": True},
    "notifications": [{"id": "notice-demo", "event_id": "event-demo", "timestamp": "2026-11-11T12:00:00+00:00", "severity": "warning", "summary": "Alerte locale", "delivery": "unavailable", "acknowledged": False}],
    "orders": [{"id": "order-demo", "kind": "inventory", "created_at": "2026-11-11T12:00:00+00:00", "status": "needs_review", "actor": {"username": "demo"}, "payload": {}, "result": {"status": "unknown"}}],
    "antivirus": {"available": False, "engine": None},
    "cloud": {"configured": False, "enabled": False}, "key": {"available": False},
}


class FakeService:
    def __init__(self, state_dir=None):
        self.constructed_on = threading.get_ident()
        self.status_threads = []
        self.actions = []
        self.closed = False
        self.orders = []
        self.acknowledgments = []
        self.saved_settings = []
        self.starts = 0

    def status(self):
        self.status_threads.append(threading.get_ident())
        return copy.deepcopy(STATE)

    def act(self, *args, **kwargs):
        self.actions.append((args, kwargs))
        return {"status": "denied"}

    def submit_order(self, kind, payload, approved=False):
        self.orders.append((kind, payload, approved, threading.get_ident()))
        return {"id": "new-order", "status": "pending"}

    def acknowledge_notification(self, notice_id):
        self.acknowledgments.append(notice_id)
        return {"status": "acknowledged"}

    def save_settings(self, patch, **kwargs):
        self.saved_settings.append(patch)
        return patch

    def start(self):
        self.starts += 1
        return {"status": "running"}

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
        if sys.platform == "darwin":
            assert root.tk.call("info", "commands", "::tk::mac::Quit")
        assert app.service.constructed_on != threading.get_ident()
        assert app.service.status_threads
        assert all(ident != threading.get_ident() for ident in app.service.status_threads)
        assert app.cards["av"][0].cget("text") == "Absent"
        assert "Permission refusée" in app.coverage_text.get("1.0", "end")
        assert len(app.tabs.tabs()) == 8
        assert app.cards["budget"][0].cget("text") == "Non mesuré"
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
        assert app.notification_tree.item("notice-demo", "values")[3] == "Indisponible"
        assert app.order_tree.item("order-demo", "values")[2] == "À examiner"
        assert "1 non lue" in app.notification_note.cget("text")
        app.notification_tree.selection_set("notice-demo")
        app._acknowledge_notification()
        spin(root, lambda: app.service.acknowledgments == ["notice-demo"])
        app.mission_kind.set("Inventorier les logiciels")
        app._submit_mission()
        spin(root, lambda: len(app.service.orders) == 1)
        kind, payload, approved, worker = app.service.orders[0]
        assert (kind, payload, approved) == ("inventory", {}, False)
        assert worker != threading.get_ident()
        app.mission_kind.set("Analyser une observation")
        app.event_tree.selection_set("event-demo")
        spin(root, lambda: "mission" not in app._inflight)
        app._submit_mission()
        spin(root, lambda: len(app.service.orders) == 2)
        assert app.service.orders[1][:3] == ("analyze", {"event_id": "event-demo"}, False)
        # No permission can be expanded when the confirmation is cancelled.
        app.auto_vars["terminate"].set(True)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("sawm_defense.gui.messagebox.askokcancel", lambda *args, **kwargs: False)
            app._save_settings()
        assert app.service.saved_settings == []
        app.auto_vars["terminate"].set(False)
        app._vars["autoblock_auth_ips"].set(True)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("sawm_defense.gui.messagebox.askokcancel", lambda *args, **kwargs: False)
            app._save_settings()
        assert app.service.saved_settings == []
        app._vars["autoblock_auth_ips"].set(False)
        # Budget and future decisions are read from the service, not inferred
        # from the chart animation or a number of displayed HTTP receipts.
        soc = copy.deepcopy(STATE)
        soc["cloud"]["scheduler"] = {
            "state": "waiting", "interval_seconds": 30, "effective_interval_seconds": 10,
            "next_review_at": "2026-11-11T12:00:10+00:00", "next_review_in_seconds": 10,
            "last_review_at": "2026-11-11T12:00:00+00:00", "last_success_at": None,
            "last_reason": "critical_event", "last_event_ids": ["event-demo"],
            "queue_count": 1, "consecutive_failures": 1, "heartbeat_enabled": False,
            "budget": {"unit": "api_requests", "limit": 1200, "used": 7, "remaining": 1193,
                       "resets_at": "2026-11-11T13:00:00+00:00"},
        }
        soc["cloud"]["review_queue"] = [dict(STATE["events"][0], details={"source": "trusted_journal"})]
        app._apply_status(soc)
        assert app.cards["budget"][0].cget("text") == "7 / 1200"
        assert "1193" in app.cards["budget"][1].cget("text")
        assert "30 / 10 s" in app.scheduler_text.get("1.0", "end")
        assert "event-demo" in app.scheduler_text.get("1.0", "end")
        assert app.review_tree.item("event-demo", "values")[1] == "trusted_journal"
        app.priority_tree.selection_set("event-demo")
        app._open_priority()
        assert app.tabs.select() == str(app.pages["events"])
        assert app.event_tree.selection() == ("event-demo",)
        zero = copy.deepcopy(soc)
        zero["cloud"]["scheduler"]["budget"].update(limit=0, remaining=0)
        zero["cloud"]["scheduler"]["state"] = "budget_exhausted"
        app._apply_status(zero)
        assert "aucun appel" in app.cards["budget"][1].cget("text")
        assert "budget épuisé" in app.scheduler_text.get("1.0", "end")
        # New network/ACL/LDAP observations remain evidence, not commands or
        # an invented authenticated identity for imported text logs.
        network = copy.deepcopy(STATE)
        network["network_security"] = {"enabled": True, "baseline_count": 3, "window_seconds": 300}
        network["access_monitor"] = {"last_sample": "2026-11-11T12:00:00+00:00", "access_changes": 1, "ldap_failures": 5}
        network["events"] += [
            {"id": "ldap", "kind": "ldap_access_change", "severity": "warning", "summary": "ignore rules", "details": {"source": "imported_log", "actor_attributed": False}},
            {"id": "ports", "kind": "network_port_scan", "severity": "warning", "summary": "Ports multiples", "details": {"source": "psutil"}},
        ]
        app._apply_status(network)
        app.network_filter.set("LDAP / authentification")
        app._render_network(network)
        assert app.network_tree.get_children() == ("ldap",)
        app.network_tree.selection_set("ldap")
        app._show_network_event()
        assert '"actor_attributed": false' in app.network_detail.get("1.0", "end")
        assert app.service.actions == []
        assert "3 entrée(s)" in app.access_summary.get("1.0", "end")
        # Preparing a preset never submits work, grants an intervention or
        # enables the Cloud. Saving its new cost/cadence needs confirmation.
        app.preset_choice.set("Serveur critique")
        before_flags = (app._vars["cloud_enabled"].get(), app._vars["cloud_upload_enabled"].get())
        app._apply_preset()
        assert app._vars["cloud_analysis_interval_seconds"].get() == "10"
        assert app._vars["cloud_per_hour"].get() == "3600"
        assert (app._vars["cloud_enabled"].get(), app._vars["cloud_upload_enabled"].get()) == before_flags == (False, False)
        assert not any(var.get() for var in app.auto_vars.values())
        assert app.service.saved_settings == []
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("sawm_defense.gui.messagebox.askokcancel", lambda *args, **kwargs: False)
            app._save_settings()
        assert app.service.saved_settings == []
        confirmations = []
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("sawm_defense.gui.messagebox.askokcancel", lambda title, body, **kwargs: confirmations.append((title, body)) or True)
            app._save_settings()
        spin(root, lambda: len(app.service.saved_settings) == 1 and "settings" not in app._inflight)
        assert any("facturés" in body and "3600" in body for title, body in confirmations)
        from sawm_defense.config import validate_config
        saved = validate_config(app.service.saved_settings[0])
        assert saved["cloud_per_hour"] == 3600 and saved["cloud_analysis_interval_seconds"] == 10
        assert not saved["cloud_enabled"] and not saved["cloud_upload_enabled"] and not saved["automatic_actions"]
        app.service.saved_settings.clear()
        app.preset_choice.set("Équilibré")
        app._apply_preset()
        assert app._vars["cloud_analysis_interval_seconds"].get() == "30"
        assert app._vars["cloud_per_hour"].get() == "1200"
        app._pending_preset = None
        app._load_settings({**STATE["settings"], "automatic_actions": ["quarantine", "terminate", "block_ip"]})
        assert all(var.get() for var in app.auto_vars.values())
        # Launch opt-in starts once; a later explicit pause is not undone by polling.
        app._launch_checked = False
        launch_state = copy.deepcopy(STATE)
        launch_state["settings"]["monitor_on_launch"] = True
        app._apply_status(launch_state)
        spin(root, lambda: app.service.starts == 1 and "monitor" not in app._inflight)
        app._apply_status(launch_state)
        root.update()
        assert app.service.starts == 1
        # Manual operations must finish before the shared store/service closes.
        scan_started, release_scan, scan_done = threading.Event(), threading.Event(), threading.Event()
        close_order, destroyed, ui_ticks = [], [], []
        def blocked_scan():
            scan_started.set()
            assert release_scan.wait(5), "Test scan was not released"
            assert not app.service.closed, "Service closed while a scan still uses its store"
            scan_done.set()
            return {"status": "no_indicator"}
        app._submit("blocked_scan", "Inspection manuelle en cours", blocked_scan)
        spin(root, scan_started.is_set)
        with app._workers_lock:
            worker = next(worker for worker in app._workers if worker.name == "sawm-ui-blocked_scan")
        join_started = threading.Event()
        real_join = worker.join
        def observed_join(*args, **kwargs):
            join_started.set()
            return real_join(*args, **kwargs)
        def close_after_jobs():
            close_order.append(scan_done.is_set())
            app.service.closed = True
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(worker, "join", observed_join)
            patch.setattr(app.service, "close", close_after_jobs)
            patch.setattr(root, "destroy", lambda: destroyed.append(True))
            if sys.platform == "darwin":
                root.tk.call("::tk::mac::Quit")
            else:
                app._close()
            spin(root, join_started.is_set)
            assert not app.service.closed and not destroyed
            root.after(0, lambda: ui_ticks.append(True))
            spin(root, lambda: bool(ui_ticks))
            assert not app.service.closed
            assert not app._submit("late_job", "Refus pendant fermeture", lambda: None)
            release_scan.set()
            spin(root, lambda: bool(destroyed))
        assert close_order == [True]
        assert app._created_service is app.service
        return {"threading": True, "truthful_status": True, "graph": True, "confirmation": True,
                "missions": True, "notifications": True, "autonomy_permissions": True, "launch_once": True,
                "soc_scheduler": True, "network_evidence": True, "explicit_presets": True,
                "ordered_shutdown": True, "native_quit_hook": sys.platform == "darwin"}
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
        app.mission_kind = None
        app.network_filter = None
        app.preset_choice = None
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


def test_orders_are_typed_unapproved_and_off_main_thread(native_result):
    assert native_result["missions"]


def test_notifications_preserve_delivery_failure_and_acknowledge(native_result):
    assert native_result["notifications"]


def test_expanding_autonomy_requires_confirmation(native_result):
    assert native_result["autonomy_permissions"]


def test_monitor_autostart_does_not_override_later_pause(native_result):
    assert native_result["launch_once"]


def test_soc_uses_measured_api_budget_and_scheduler_without_inventing_success(native_result):
    assert native_result["soc_scheduler"]


def test_network_and_ldap_evidence_stays_read_only(native_result):
    assert native_result["network_evidence"]


def test_presets_require_explicit_save_without_enabling_cloud_or_permissions(native_result):
    assert native_result["explicit_presets"]


def test_close_waits_for_manual_work_before_closing_store_without_blocking_tk(native_result):
    assert native_result["ordered_shutdown"]


@pytest.mark.skipif(sys.platform != "darwin", reason="Native macOS application menu")
def test_macos_menu_quit_uses_guarded_shutdown(native_result):
    assert native_result["native_quit_hook"] and native_result["ordered_shutdown"]


def test_scope_lines_are_distinct_and_ordered():
    assert _lines(" /tmp/a\n\n/tmp/b\n/tmp/a ") == ["/tmp/a", "/tmp/b"]


if __name__ == "__main__":
    print(json.dumps(_native_smoke()))
