# Smart OS Guardian (MVP build)

A Linux-inspired AI security workstation for **Windows 10 / 11**. Not a new OS or kernel: a local-first endpoint monitor
(Python agent + FastAPI + SQLite) with a tiling-WM / tmux / htop style desktop UI. Built from *Smart OS Guardian – Detailed Proposal v3*.

## Quick start (Windows)
1. Install Python 3.10+ (tick "Add to PATH").
2. Double-click **`install.bat`** (creates `.venv`, installs deps, runs self-tests).
3. Double-click **`run.bat`** (or **`run_admin.bat`** for Security-log access). The desktop shell opens in an Edge/Chrome app window.

It uses **real data from your PC immediately**: process inventory and start/stop events, resource usage, network connections,
Windows Event Log (System, Security if elevated, Defender), startup (Run) keys, and Sysmon if installed. No internet needed.

## What you get (MVP scope, proposal §3.1)
| Area | Implemented |
|---|---|
| Telemetry | psutil process/resource/network, Event Log via `wevtutil`, Defender observations, Run-key watcher, optional Sysmon (`deployment/sysmon-config`) |
| Pipeline | normalised event envelope v1 (UTC, redaction), bounded queue (10k / 32 MB, 70 % warn, 90 % shed, drop counters), batched WAL writes, retention, DB cap |
| Storage | SQLite WAL, forward-only migrations with backup/restore, hash-chained audit log |
| Detection | rules E2–E6 + PE model slot E1, correlation policy v1 (`detection/policy/policy_v1.json`), explainable incidents with caveats |
| AI | PE model: **empty until you provide the dataset** -> rules-only mode. Training/calibration/model-card pipeline ready in `ai/malware-pe/` |
| API | loopback only, random port, 256-bit per-session token, Host/Origin checks, rate limit, schema validation, no execute endpoint |
| UI | boot log, top panel, dock, floating/tiling windows, htop-style Process Center, `ss`-style Network Center, journalctl-style timeline, read-only Guardian Terminal, rofi-style palette (Ctrl+K), light/dark |

## Keyboard
`Ctrl+K` palette · `Alt+1..9` switch window · `Alt+T` tile · `Alt+W` close · Process Center `F3/F5/F6/F9/F10` · Terminal: Tab, ↑/↓, `Ctrl+L`.

## When you provide the dataset
See `ai/malware-pe/README.md`. Short version: put the data in, run `train_run.bat ...`, restart; Model Lab shows the model card.
Nothing else in the app changes: until then, incidents state "No PE model installed".

## Safe demo without malware
Security Center -> *safe scenario* -> **run**. Replays labelled **SIM** synthetic events (nothing is executed) to show a linked incident
(Office -> PowerShell -> unsigned dropper -> outbound -> Run key). `benign_dev_tools` shows noise staying quiet.

## Honest limitations
* Collection is diff/polling based (2–3 s) plus Event Log polling (10 s); ETW/C++ collector is deferred until profiling shows a need.
* Signer check uses PowerShell `Get-AuthenticodeSignature` (low-priority, cached); file-create/registry attribution needs Sysmon.
* Response actions are **preview-only** by design (D3). Cloud/central mode, network IDS, anomaly model are deferred (D1–D5).
* Unsigned installer; autostart via `deployment/installer/autostart.ps1`. Not validated on ARM64/Server.
* Windows-specific code paths were written against documented APIs and fixture-tested, but this build was exercised on Linux in dev mode;
  please run `install.bat` self-tests and report anything odd on your Windows build (Milestone M1/M2 24 h runs are still yours to do).

## Layout
`agent/python-agent/guardian` core · `apps/desktop-ui` UI (no build step) · `ai/malware-pe` training · `detection/policy` rules weights ·
`database/migrations` · `deployment` · `tests` · `docs` · `testbed`.
