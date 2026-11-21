"""Guardian Terminal: a controlled, read-only command set. No arbitrary shell execution (spec 4.1, 17.1)."""
from __future__ import annotations
import shlex, time, json
from . import config, pe, normalize

HELP = """Guardian commands (read-only in the MVP)
  help                      show this list
  status                    agent, database, queue and model health
  sources                   telemetry sources and their capability state
  system                    CPU / RAM / disk summary
  processes [--top N]       top resource-consuming processes
  alerts [--recent]         recent incidents
  timeline [--hours N]      recent correlated activity
  scan --file <path>        analyse file metadata (parsed, never executed)
  models                    installed model versions
  privacy                   telemetry and retention settings
  version | clear | exit"""


def _fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def run(agent, line: str) -> dict:
    try:
        parts = shlex.split(line, posix=not config.IS_WINDOWS)
    except ValueError as e:
        return {"ok": False, "output": f"parse error: {e}"}
    if not parts:
        return {"ok": True, "output": ""}
    cmd, args = parts[0].lower(), parts[1:]

    def opt(name, default=None):
        if name in args:
            i = args.index(name)
            return args[i + 1] if i + 1 < len(args) else default
        return default

    if cmd == "help":
        return {"ok": True, "output": HELP}
    if cmd == "version":
        return {"ok": True, "output": f"Smart OS Guardian {config.VERSION}  policy {agent.engine.policy['policy_version']}"}
    if cmd == "status":
        h = agent.health()
        q = h["queue"]
        lines = [f"agent      : {h['status']}  (paused={h['paused']})  uptime {h['uptime_s']}s",
                 f"host       : {h['hostname']}  {h['os']} {h['architecture']}  admin={h['admin']}",
                 f"database   : {_fmt_bytes(h['db']['size_bytes'])}  read_only={h['db']['read_only']}  audit_chain_ok={h['db']['audit_chain_ok']}",
                 f"queue      : {q['depth']} events  {q['fill_pct']}%  state={q['state']}  dropped={q['dropped']} ({q['drop_rate_pct']}%)",
                 f"model      : {'loaded ' + h['model'].get('version', '') if h['model']['loaded'] else 'none installed - rules-only'}",
                 f"degraded   : {', '.join(h['degraded']) or '-'}", f"unavailable: {', '.join(h['unavailable']) or '-'}"]
        return {"ok": True, "output": "\n".join(lines)}
    if cmd == "sources":
        rows = [f"{k:<20} {v['status']:<12} {v.get('reason', '')}" for k, v in agent.sources_health().items()]
        return {"ok": True, "output": "\n".join(rows)}
    if cmd == "system":
        s = agent.resources.latest() if agent.resources else None
        if not s:
            return {"ok": False, "output": "no sample yet"}
        return {"ok": True, "output": f"cpu   {s['cpu']:.1f}%  ({s['cpu_count']} cores)\nmem   {s['mem']:.1f}%  {_fmt_bytes(s['mem_used'])} / {_fmt_bytes(s['mem_total'])}\n"
                                      f"disk  {s['disk']}%  free {_fmt_bytes(s['disk_free'])}\nuptime {int(s['uptime'] // 3600)}h {int(s['uptime'] % 3600 // 60)}m\nprocs {s['load_procs']}"}
    if cmd == "processes":
        n = int(opt("--top", 20) or 20)
        rows = sorted(agent.procs.values(), key=lambda v: v.get("rss", 0), reverse=True)[:max(1, min(n, 100))]
        out = [f"{'PID':>7} {'CPU%':>5} {'RSS':>9}  {'SIGNER':<9} NAME"]
        out += [f"{p['pid']:>7} {p.get('cpu', 0):>5.1f} {_fmt_bytes(p.get('rss', 0)):>9}  {p.get('signer', '?'):<9} {p['name']}" for p in rows]
        return {"ok": True, "output": "\n".join(out)}
    if cmd == "alerts":
        rows = agent.db.query("SELECT incident_id, severity, status, title, opened_at FROM incidents ORDER BY opened_at DESC LIMIT 15")
        if not rows:
            return {"ok": True, "output": "no incidents"}
        return {"ok": True, "output": "\n".join(f"{r['incident_id']}  {r['severity'].upper():<13} {r['status']:<13} {r['title']}" for r in rows)}
    if cmd == "timeline":
        hours = float(opt("--hours", 2) or 2)
        rows = agent.db.query("SELECT ts, source, event_type, image_path, attributes FROM events WHERE ts>? ORDER BY ts DESC LIMIT 40",
                              (time.time() - hours * 3600,))
        out = []
        for r in reversed(rows):
            a = json.loads(r["attributes"] or "{}")
            out.append(f"{time.strftime('%H:%M:%S', time.localtime(r['ts']))} {r['source']:<13} {r['event_type']:<18} {a.get('name') or r['image_path'] or ''}")
        return {"ok": True, "output": "\n".join(out) or "no events in range"}
    if cmd == "scan":
        path = opt("--file")
        if not path:
            return {"ok": False, "output": "usage: scan --file <path>"}
        res = pe.scan_file(path, agent.model)
        f = res["file"]
        if not f.get("exists"):
            return {"ok": False, "output": f"not a file: {path}"}
        lines = [f"file     {normalize.redact_path(f['path'])[0]}", f"size     {_fmt_bytes(f['size'])}", f"sha256   {f['sha256']}",
                 f"PE       {f.get('is_pe')}   executed: never", f"model    {res['model_status']}"]
        if f.get("sections"):
            lines.append("sections " + ", ".join(f"{s['name']}(H={s['entropy']})" for s in f["sections"]))
            if f["high_entropy_sections"]:
                lines.append("note     high-entropy sections: " + ", ".join(f["high_entropy_sections"]) + " (packed/encrypted possible; not proof)")
        if res["model"]:
            m = res["model"]
            lines.append(f"score    {m['score']} (threshold {m['threshold']}, model {m['model_version']}, {m['inference_time_ms']} ms)")
        return {"ok": True, "output": "\n".join(lines)}
    if cmd == "models":
        h = agent.model
        return {"ok": True, "output": (f"malware-pe {h.info['version']}  schema {h.info['feature_schema_version']}  sha256 {h.info['hash'][:16]}…"
                                       if h.loaded else "no models installed. Place a trained package in ai/model-registry/malware-pe/<version>/ (see ai/malware-pe/README.md)")
                                      + (f"\nwarning: {h.warning}" if h.warning else "")}
    if cmd == "privacy":
        return {"ok": True, "output": "\n".join(f"{k:<24} {v}" for k, v in agent.privacy.items())}
    return {"ok": False, "output": f"guardian: command not found: {cmd}  (type 'help'; arbitrary shell execution is disabled)"}
