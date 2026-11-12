"""Real Linux firewall exercise, inside new mount AND network namespaces only.

The synthetic peer uses an address assigned exclusively inside this disconnected
lab. No Internet route, physical interface, host firewall rule or Cloud account
is used. Requires an explicitly invoked disposable Linux root test runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PEER = "93.184.216.34"  # Synthetic assignment; never routed outside the lab.
PORT = 18763


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args, timeout=10):
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout,
                            env={**os.environ, "LC_ALL": "C.UTF-8"})
    require(result.returncode == 0, "Lab prerequisite/command failed: " + args[0] + " " + result.stderr[-600:])
    return result.stdout


def connect():
    try:
        with socket.create_connection((PEER, PORT), timeout=1.5) as client:
            client.sendall(b"sawm-harmless-fixture")
            return client.recv(32) == b"fixture-ok"
    except OSError:
        return False


def host_fingerprint():
    digest = hashlib.sha256()
    for base in (Path("/etc/ufw"), Path("/etc/default/ufw")):
        items = sorted(base.rglob("*")) if base.is_dir() else [base]
        for path in items:
            if path.is_file() and not path.is_symlink():
                digest.update(str(path).encode())
                digest.update(path.read_bytes())
    # iptables-save includes generation timestamps and live packet counters.
    # Compare policy, not incidental traffic/time during an otherwise idle test.
    policies = {}
    for executable in ("iptables-save", "ip6tables-save"):
        if not shutil.which(executable):
            continue
        lines = [re.sub(r"\[\d+:\d+\]", "[COUNTERS]", line)
                 for line in run(executable).splitlines() if line and not line.startswith("#")]
        policies[executable] = "\n".join(lines)
    return {"config_sha256": digest.hexdigest(),
            "firewall_sha256": hashlib.sha256(json.dumps(policies, sort_keys=True).encode()).hexdigest()}


def isolated(host_netns, host_mountns):
    require(os.readlink("/proc/self/ns/net") != host_netns, "Refuse host network namespace")
    require(os.readlink("/proc/self/ns/mnt") != host_mountns, "Refuse host mount namespace")
    interfaces = json.loads(run("ip", "-json", "link", "show"))
    require({row["ifname"] for row in interfaces} == {"lo"}, "Namespace is not an empty isolated network")
    run("mount", "--make-rprivate", "/")
    peer_process = server = agent = client = None
    with tempfile.TemporaryDirectory(prefix="sawm-firewall-lab-") as temporary:
        work = Path(temporary)
        cloned = work / "ufw"
        shutil.copytree("/etc/ufw", cloned)
        default = work / "default-ufw"
        default.write_text(Path("/etc/default/ufw").read_text().replace("IPV6=yes", "IPV6=no"))
        run("mount", "--bind", str(cloned), "/etc/ufw")
        run("mount", "--bind", str(default), "/etc/default/ufw")
        # Ubuntu may resolve /etc/resolv.conf through /run/systemd/resolve.
        # Preserve a private readable copy after isolating /run so the executor
        # can still enforce its DNS-protection check, without host modification.
        resolver_target = Path("/etc/resolv.conf").resolve(strict=True)
        resolver = work / "resolv.conf"
        resolver.write_bytes(resolver_target.read_bytes())
        run("mount", "-t", "tmpfs", "tmpfs", "/run")
        if resolver_target.is_relative_to("/run"):
            resolver_target.parent.mkdir(parents=True, exist_ok=True)
            resolver_target.touch()
        run("mount", "--bind", str(resolver), str(resolver_target))
        try:
            run("ip", "link", "set", "lo", "up")
            peer_process = subprocess.Popen(["unshare", "--net", "sleep", "90"])
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    if os.readlink(f"/proc/{peer_process.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                        break
                except OSError:
                    pass
                time.sleep(.02)
            require(peer_process.poll() is None, "Peer namespace did not start")
            require(os.readlink(f"/proc/{peer_process.pid}/ns/net") != os.readlink("/proc/self/ns/net"),
                    "Peer did not enter its separate network namespace")
            run("ip", "link", "add", "sawm-test", "type", "veth", "peer", "name", "sawm-peer")
            run("ip", "link", "set", "sawm-peer", "netns", str(peer_process.pid))
            run("ip", "address", "add", "93.184.216.33/30", "dev", "sawm-test")
            run("ip", "link", "set", "sawm-test", "up")
            enter = ["nsenter", "-t", str(peer_process.pid), "-n"]
            run(*enter, "ip", "link", "set", "lo", "up")
            run(*enter, "ip", "address", "add", PEER + "/30", "dev", "sawm-peer")
            run(*enter, "ip", "link", "set", "sawm-peer", "up")
            require(not run("ip", "route", "show", "default").strip(), "Lab must not have an Internet route")
            server_code = """import socketserver
class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  self.request.settimeout(20)
  try:
   if self.request.recv(64): self.request.sendall(b'fixture-ok')
  except OSError: pass
class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=True
 daemon_threads=True
Server(('0.0.0.0',18763),Handler).serve_forever()
"""
            server = subprocess.Popen([*enter, sys.executable, "-c", server_code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not connect():
                time.sleep(.1)
            require(connect(), "Synthetic peer not reachable before test")
            run("ufw", "default", "allow", "incoming")
            run("ufw", "default", "allow", "outgoing")
            run("ufw", "--force", "enable", timeout=20)
            require(connect(), "Baseline peer not reachable with isolated UFW")
            from sawm_defense.service import AgentService
            from sawm_defense.policy import authorize
            agent = AgentService(work / "state")
            agent.save_settings({"cloud_enabled": False, "cloud_upload_enabled": False,
                "cloud_base_url": "http://localhost", "cloud_per_hour": 0, "monitor_paths": [],
                "protect_downloads": False, "notifications_enabled": False, "poll_seconds": 1,
                "network_security_enabled": True, "denied_remote_ips": [PEER],
                "allowed_remote_ips": [PEER], "automatic_actions": ["block_ip"],
                "autoblock_network_policy": True, "auto_block_seconds": 60})
            # Hold a real socket long enough for the actual OS collector to see it.
            client = socket.create_connection((PEER, PORT), timeout=2)
            started = time.monotonic()
            agent.start()
            action = None
            deadline = started + 20
            while time.monotonic() < deadline:
                action = next((a for a in agent.store.actions() if a.get("action") == "block_ip" and a.get("status") == "completed"), None)
                if action:
                    break
                time.sleep(.1)
            require(action is not None, "Autonomous authorized firewall block did not complete")
            elapsed = time.monotonic() - started
            event = next((e for e in agent.store.events() if e.get("kind") == "network_policy_violation"), None)
            require(event is not None and event["details"]["verified_local"], "No local OS socket evidence")
            client.close(); client = None
            require(not connect(), "New TCP connection remains possible after block")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not any(n.get("event_id") == event["id"] for n in agent.notifications.list()):
                time.sleep(.1)
            require(any(n.get("event_id") == event["id"] for n in agent.notifications.list()), "No persistent alert for the violation")
            current = agent.settings()
            require(not authorize("block_ip", event, {**current, "automatic_actions": []})[0], "Missing authorization accepted")
            require(not authorize("block_ip", event, {**current, "protected_remote_ips": [PEER]})[0], "Protected IP accepted")
            require(agent.stop().get("status") == "completed", "Agent did not stop before rollback")
            restored = agent.executor.rollback(action, current)
            require(restored.get("status") == "completed", "Firewall rollback not verified")
            require(connect(), "Peer communication not restored after rollback")
            require(agent.store.verify_chain().get("ok") is True, "Journal integrity failed")
            require(not agent.store.calls(), "Cloud call in an offline isolated lab")
            return {"status": "passed", "version": "0.3.0", "test": "isolated_linux_native_firewall",
                "real_os_socket_detected": True, "persistent_alert": True, "autonomous_policy_block": True,
                "new_tcp_connection_blocked": True, "rollback_verified": True, "tcp_communication_restored": True,
                "missing_authorization_refused": True, "protected_ip_refused": True, "journal_verified": True,
                "cloud_calls": 0, "time_to_authorized_block_seconds": round(elapsed, 3),
                "isolation": "new network and mount namespaces; synthetic peer; no default route",
                "limits": "Tests a declared denied destination, not general malware or intrusion classification. No Cloud inference."}
        finally:
            if client:
                client.close()
            if agent:
                agent.close()
            for child in (server, peer_process):
                if child and child.poll() is None:
                    child.terminate()
                    try: child.wait(timeout=3)
                    except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--isolated-child", action="store_true")
    parser.add_argument("--host-netns")
    parser.add_argument("--host-mountns")
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0, "Explicit disposable Linux root runner required")
    if args.isolated_child:
        print(json.dumps(isolated(args.host_netns, args.host_mountns)))
        return
    require(args.output is not None, "An output proof path is required")
    before = host_fingerprint()
    child = subprocess.Popen(["unshare", "--mount", "--net", "--fork", "--kill-child=KILL", sys.executable,
        str(Path(__file__).resolve()), "--isolated-child", "--host-netns", os.readlink("/proc/self/ns/net"),
        "--host-mountns", os.readlink("/proc/self/ns/mnt")], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", start_new_session=True)
    timed_out = False
    try:
        output, error = child.communicate(timeout=85)
    except subprocess.TimeoutExpired:
        timed_out = True
        # Only this test's new session/group, including its peer/server descendants.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            output, error = child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, error = child.communicate(timeout=2)
    finally:
        after = host_fingerprint()
        require(before == after, "Host firewall or configuration changed during isolated test")
    require(not timed_out, "Isolated lab exceeded its time budget; owned process group terminated")
    require(child.returncode == 0, "Isolated lab failed: " + error[-3000:])
    proof = json.loads(output)
    proof["host_firewall_and_configuration_unchanged"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    main()
