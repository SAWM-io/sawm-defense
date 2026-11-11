# Implementation contract

Initial desktop + CLI release. Python 3.12+, tkinter/ttk desktop, psutil OS observations, public Basira HTTP SDK, OS keyring credentials. Source package `sawm_defense`. All local state under platform user data directory by default; `--state-dir` overrides for tests. No modifications outside explicit monitored paths/action grants. No generic shell execution from Cloud text.

## Common data

Event dict: `id` string, `timestamp` UTC ISO, `kind` string, `severity` (`info`,`warning`,`critical`), `summary` string, `details` dict. Store assigns missing id/time. Sensor observations are facts, never authorization. Snapshot dict: `platform`, `cpu_percent`, `memory_percent`, `processes` (bounded list of pid/name/username/create_time/exe), `connections` (bounded list pid/local/remote/status), `capabilities` list of {name,available,reason}, `coverage` dict, `sampled_at`. Missing permissions explicit.

Config defaults: `cloud_enabled=False`, `cloud_upload_enabled=False`, `cloud_base_url=https://basira-api.sawm.io/api/v1/basira`, `space_id=''`, `entity_id=''`, `monitor_paths=[]`, `poll_seconds=5`, `cloud_per_hour=4`, `automatic_actions=[]`, `allowed_process_paths=[]`, `allowed_remote_ips=[]`, `protected_paths=[]`, `max_file_mb=100`, `retention_days=30`. API key NEVER in config or logs. Automatic action types subset `quarantine`, `terminate`, `block_ip`; defaults empty. Individual network blocks never blanket interface shutdown. Automatic action requires verified local antivirus detection attached to that exact event/target; mere anomaly or LLM confidence insufficient. Manual approval can authorize a scoped anomaly response. Secrets unavailable means memory-only key or explicit error, no plaintext fallback.

## Storage + Cloud agent owns

`config.py`: `default_state_dir() -> Path`, `ConfigManager(state_dir)` with `load()->dict`, `save(patch)->dict` strict whitelist validation; properties state_dir/config_path.

`storage.py`: `Store(state_dir)` thread-safe SQLite, `add_event(event)->dict`, `events(limit=100)->list newestfirst`, `get_event(id)->dict|None`, `record_action(dict)->dict`, `actions(limit=100)->list`, `enqueue(event)->None`, `pending(limit=20)->list`, `ack_pending(ids)->None`, `record_call(dict)`, `calls(limit=100)->list`, `reserve_cloud(limit_per_hour)->bool` persistent bounded budget, `verify_chain()->dict`, `prune(days)->dict`. Journal integrity hash chain detects casual edits, not hostile root; retained anchor needed if pruning. All state owner-only. Raw file contents never sent automatically.

`secrets.py`: `SecretVault(state_dir)` exposes `get()->str|None`, `set(key,persist=True)->dict` `{persisted,backend}`, `delete()`, keyring identity perstate and no secrets in exceptions. `persist=False` in-memory.

`cloud.py`: `CloudBridge(config:dict, api_key:str, record_call:callable)` actual publicSDK; `check()->dict` read-only access entity/TSST/ODVL capabilities; `upload(events)->dict` jobs polling bounded and idempotent stableeventids; `analyze(events,permissions)->dict` SAWM SSE terminalrequired typed JSON only `{summary,action,event_id,reason,uncertainties}`, action `observe,quarantine,terminate,block_ip`; `chat(message,events)->dict {text,usage,memory}`. Validate scope and evidence identities. Timeouts, no automatic retries of incomplete mutations, no raw credentials logged. `close()`. No live Cloud by subagent.

## Platform agent owns

`platforms.py`: `Collector(config)` `sample()->tuple[snapshot,events]`, `update_config(config)`. Poll bounded paths for create/modify/delete, SHA256 metadata with strict scope/no symlink traversal/max size/max count; psutil resources/processes/network; installed-program inventory via native readonly commands bounded timeout on explicit `inventory()` (not everytick). `capabilities()->list` truthful coverage.

`antivirus.py`: `Antivirus()` `capabilities()->dict`, `scan(path:Path)->dict {status:clean|detected|unavailable|error,engine,path,sha256,detections}` uses real installed ClamAV or Defender. No claim all-malware if hash-only or backendabsent. ClamAV exit2 is error. No installation/download of AV secretly. Scan scope enforced by Service. Protect scanner-induced quarantines on Defender: scan-only DisableRemediation. Bounded timeout.

`actions.py`: `ActionExecutor(state_dir)` `execute(action:str,event:dict,config:dict)->dict` root serviceauthorizes first, executor revalidates scope/identity/protectedpath; quarantine singlefile under monitoredroots/hash/size/symlink check; reversible restore via `restore(action_record,config)->dict` explicit, fails if destination exists. terminate only own-user pid creationtime + exe allowlist fingerprint, neverself/system/protected; block_ip exact allowed_publicIP with admin and local firewall native supports, no cloud/DNS/default/network ranges, ruleidentifier+rollback `rollback(record,config)`. Every unsupported/denied returnstatus not pretend success. stdout sanitized; no shell=True.

`autorun.py`: `startup_plan(executable:list[str],state_dir)->dict`, `install_startup(executable,state_dir)->dict`, `remove_startup(state_dir)->dict`: user-level supervised systemd/LaunchAgent/ScheduledTask for `watch`; explicitopt-in only; refuse overwrite unrelated service. No root installation/security weakening.

## Root owns

`service.py`: `AgentService(state_dir=None)` orchestrates all; no live Cloud bydefault. Methods `settings()->dict`, `save_settings(patch,api_key=None,persist_key=True)`, `status()->dict`, `tick()->dict`, `start()`, `stop()`, `check_connection()->dict`, `scan(path)->dict`, `inventory()->dict`, `analyze(event_id=None)->dict`, `chat(message)->dict`, `act(action,event_id,approved=False)->dict`, `restore(action_id,approved=False)`, `export_report(path)->str`, `install_startup()->dict`, `remove_startup()->dict`, `close()`.

`status`: `running`, `settings` safeconfig, `snapshot`, `events`, `actions`, `calls`, `cloud` {configured,enabled,status,last_error}, `journal`, `antivirus`, `key` {available,persisted/backend nosecret}. GUI nevercalls operations onUIthread.

## GUI agent owns

`gui.py`: `main(state_dir=None)`, tkinter/ttk polished black/white/gray native window, no dependency onWebserver. Uses `AgentService` methods above; noautostart actionsprivileged. Onboarding fields cloudbase/space/entity/keymasked, monitorfolderpicker, permissionsselect andsaves; status tells observations coverage/Cloud/AVmissing. Tabs overview/files+network/settings/chat/activity; responsivepanes scroll; charts TkCanvas CPU/RAM withactualhistory. Workerqueue tokeepUIresponsive; refresh status safe; explicit manualconfirmation foractions/restore and startup, stringsuntrusted renderedtext. Flexiblelanguage Frenchdefault. CLIhandledroot. Reuse same service, no new RESTserver.

## Packaging

Root builds local macOS .app/.zip or .dmg via PyInstaller, user installation script and CLI. Windows/Linux packaged with CI matrix and installation docs; do notclaim built/tested WindowsLinux withoutactual evidence. No code signing credentials present; label unsigned currentMac artifact. Shiplicense/source notices of publicSDK. No proprietary engine internals.
