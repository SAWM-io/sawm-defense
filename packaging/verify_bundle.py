"""Exercise an actual bundled CLI on disposable files, with Cloud disabled."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sawm-bundle-proof-") as work:
        folder = Path(work).resolve()
        state = folder / "state"
        observed = folder / "observed"
        observed.mkdir()
        target = observed / "harmless-demo.txt"
        target.write_text("baseline")
        base = [str(args.binary.resolve()), "--state-dir", str(state)]
        def call(*parts):
            done = subprocess.run([*base, *map(str,parts)], check=True, capture_output=True, text=True, timeout=30)
            return json.loads(done.stdout)
        call("configure", "--watch-path", observed, "--no-cloud", "--no-upload-events")
        config = json.loads((state / "config.json").read_text())
        config["poll_seconds"] = 1
        (state / "config.json").write_text(json.dumps(config))
        watch = subprocess.Popen([*base, "watch", "--seconds", "9"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def events():
            with sqlite3.connect(state / "evidence.sqlite3") as db:
                return [json.loads(row[0]) for row in db.execute("select payload from ledger where kind='event' order by seq")]
        def wait_for(fn):
            deadline = time.monotonic()+7
            while time.monotonic()<deadline:
                value=fn()
                if value: return value
                time.sleep(.1)
            raise AssertionError("Expected observation not received")
        try:
            wait_for(lambda:(state / "last-snapshot.json").exists())
            target.write_text("modified harmless demonstration")
            modified = wait_for(lambda:next((e for e in events() if e["kind"]=="file_modified"),None))
            action = call("act", "quarantine", modified["id"], "--approve")
            assert action["status"]=="completed" and not target.exists(), action
            restored = call("restore", action["id"], "--approve")
            assert restored["status"]=="completed" and target.read_text()=="modified harmless demonstration", restored
            target.unlink()
            wait_for(lambda:any(e["kind"]=="file_deleted" for e in events()))
            out,err=watch.communicate(timeout=12)
            assert watch.returncode==0, err
            status=call("status")
            call("report", folder / "proof.html")
            result={"binary_version":"0.1.0","platform":"macOS Apple Silicon",
                    "packaged_cli":True,"file_change_detected":True,"manual_quarantine_verified":True,
                    "restore_verified":True,"deletion_detected":True,"bounded_watch_exit_code":watch.returncode,
                    "journal_verified":status["journal"]["ok"],"events_recorded":len(status["events"]),
                    "actions_recorded":len(status["actions"]),"cloud_calls":len(status["calls"]),
                    "report_exported":(folder/"proof.html").exists(),"cloud_enabled":False,
                    "antivirus_engine_available":status["antivirus"]["available"],
                    "notes":"Harmless files; no real malware, firewall changes or Cloud credentials."}
        finally:
            if watch.poll() is None:
                watch.terminate()
                watch.wait(timeout=10)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
        print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
