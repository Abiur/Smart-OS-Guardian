"""Process inventory + start/end events by diffing the live process table (psutil)."""
from __future__ import annotations
import os, time
from .base import Collector
from .. import config

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def process_key(pid: int, create_time: float) -> str:
    """PIDs get reused, so identity = pid + start time (spec 9.1)."""
    return f"{pid}:{int(create_time * 1000)}"


def file_created_ts(path: str | None) -> float | None:
    try:
        st = os.stat(path)
        return getattr(st, "st_birthtime", st.st_ctime)
    except (OSError, TypeError):
        return None


class ProcessCollector(Collector):
    name_id = "processes"
    interval = 2.0

    def setup(self):
        self.first = True
        self.last_snapshot = 0.0
        self.cpu_primed = False

    def tick(self):
        a = self.agent
        now = time.time()
        seen = {}
        attrs = ["pid", "ppid", "name", "exe", "create_time", "memory_info", "cpu_percent", "username", "status"]
        for p in psutil.process_iter(attrs, ad_value=None):
            i = p.info
            if i.get("pid") is None or i.get("create_time") is None:
                continue
            key = process_key(i["pid"], i["create_time"])
            seen[key] = i
        table = a.procs
        # ended
        for key in list(table.keys()):
            if key not in seen and not table[key].get("simulated"):
                pi = table.pop(key)
                a.emit("psutil", "process_end", pid=pi["pid"], process_key=key, image_path=pi.get("exe"),
                       sha256=pi.get("sha256"), attributes={"name": pi["name"]}, ts=now)
        # started
        for key, i in seen.items():
            if key in table:
                pi = table[key]
                pi["cpu"] = i.get("cpu_percent") or 0.0
                mi = i.get("memory_info")
                pi["rss"] = mi.rss if mi else 0
                continue
            exe = i.get("exe")
            ppid = i.get("ppid") or 0
            parent_key = next((k for k, v in table.items() if v["pid"] == ppid), None)
            parent = table.get(parent_key) if parent_key else None
            if parent is None:
                for k2, i2 in seen.items():
                    if i2["pid"] == ppid:
                        parent = {"name": (i2.get("name") or "").lower(), "key": k2}
                        parent_key = k2
                        break
            enr = a.enricher.get(exe)
            mi = i.get("memory_info")
            pi = {"key": key, "pid": i["pid"], "ppid": ppid, "parent_key": parent_key,
                  "parent_name": (parent or {}).get("name", "") if parent else "",
                  "name": (i.get("name") or "").lower(), "exe": exe, "start_ts": i["create_time"],
                  "exe_created_ts": file_created_ts(exe), "preexisting": self.first,
                  "sha256": enr.get("sha256"), "signer": enr.get("signer", "unknown"),
                  "cpu": i.get("cpu_percent") or 0.0, "rss": mi.rss if mi else 0, "cmdline": None,
                  "simulated": False, "first_outbound_ts": None}
            if not self.first:
                try:
                    pi["cmdline"] = " ".join(psutil.Process(i["pid"]).cmdline())
                except (psutil.Error, OSError):
                    pass
            table[key] = pi
            if exe:
                a.enricher.request(exe, want_signer=a.wants_signer(exe))
            if not self.first:
                a.emit("psutil", "process_start", pid=pi["pid"], parent_pid=ppid, process_key=key, image_path=exe,
                       sha256=pi["sha256"], ts=pi["start_ts"],
                       attributes={"name": pi["name"], "parent_name": pi["parent_name"], "command_line": pi["cmdline"],
                                   "exe_created_ts": pi["exe_created_ts"]})
        self.first = False
        # periodic top-N snapshots for trend (spec: process_snapshots, 7 d retention)
        if now - self.last_snapshot > 60:
            self.last_snapshot = now
            top = sorted(table.values(), key=lambda v: v.get("rss", 0), reverse=True)[:30]
            rows = [(a.host_id, now, v["pid"], v["key"], v["name"], v.get("exe"), v.get("sha256"), v.get("signer"),
                     v.get("cpu"), v.get("rss")) for v in top]
            try:
                with a.db.lock:
                    a.db.conn.executemany(
                        "INSERT INTO process_snapshots(host_id,ts,pid,process_key,name,image,sha256,signer,cpu,rss) VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
            except Exception:
                pass
