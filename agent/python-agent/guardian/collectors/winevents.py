"""Windows Event Log + Sysmon + Defender ingestion through wevtutil (no extra dependencies).

Only security-relevant Event IDs are kept; everything else is ignored (privacy: no unrelated personal data).
"""
from __future__ import annotations
import subprocess, time, re
import xml.etree.ElementTree as ET
from .base import Collector
from .. import config

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"

# channel -> event ids worth keeping
WANTED = {
    "System": {104, 7045, 7036},
    "Security": {1102},
    SYSMON: {1, 3, 4, 7, 8, 10, 11, 12, 13, 14, 16, 19, 20, 21, 22, 25},
    DEFENDER: {1116, 1117},
}
RUN_KEY = re.compile(r"(?i)\\(Microsoft\\Windows\\CurrentVersion\\Run(Once)?|Microsoft\\Windows NT\\CurrentVersion\\Winlogon)")


def parse_events(xml_text: str) -> list[dict]:
    """Parse concatenated <Event> elements (wevtutil output) into dicts. Public for fixture tests."""
    out = []
    try:
        root = ET.fromstring("<root>" + xml_text + "</root>")
    except ET.ParseError:
        return out
    for ev in root.findall(f"{NS}Event"):
        sysn = ev.find(f"{NS}System")
        if sysn is None:
            continue
        eid = int(sysn.findtext(f"{NS}EventID") or 0)
        tc = sysn.find(f"{NS}TimeCreated")
        chan = sysn.findtext(f"{NS}Channel") or ""
        data = {d.get("Name") or f"d{i}": (d.text or "") for i, d in enumerate(ev.iter(f"{NS}Data"))}
        out.append({"event_id": eid, "channel": chan, "time": tc.get("SystemTime") if tc is not None else None,
                    "data": data, "record": sysn.findtext(f"{NS}EventRecordID")})
    return out


def parse_iso(s: str | None) -> float:
    import datetime as dt
    if not s:
        return time.time()
    s = s.rstrip("Z")
    if "." in s:
        a, b = s.split(".")
        s = a + "." + b[:6]
    try:
        return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return time.time()


def map_event(rec: dict) -> tuple[str, dict] | None:
    """Map a raw record to (event_type, kwargs for make_event). Public for fixture tests (spec M2 exit criterion)."""
    eid, ch, d = rec["event_id"], rec["channel"], rec["data"]
    img = d.get("Image") or d.get("SourceImage")
    pid = int(d["ProcessId"]) if str(d.get("ProcessId", "")).isdigit() else None
    base = {"ts": parse_iso(rec["time"]), "image_path": img, "pid": pid}
    if ch == "System" and eid == 104:
        return "sensor_tamper", {**base, "attributes": {"kind": "log_cleared", "log": "System", "event_id": 104}}
    if ch == "Security" and eid == 1102:
        return "sensor_tamper", {**base, "attributes": {"kind": "log_cleared", "log": "Security", "event_id": 1102}}
    if ch == "System" and eid == 7045:
        return "windows_event", {**base, "attributes": {"kind": "service_installed", "service": d.get("ServiceName"),
                                                         "image": d.get("ImagePath"), "event_id": 7045}}
    if ch == "System" and eid == 7036:
        name = (d.get("param1") or "")
        if any(k in name.lower() for k in ("sysmon", "windefend", "guardian")):
            return "windows_event", {**base, "attributes": {"kind": "service_state", "service": name, "state": d.get("param2"), "event_id": 7036}}
        return None
    if ch == DEFENDER:
        return "defender_detection", {**base, "attributes": {"kind": "defender", "threat": d.get("Threat Name") or d.get("ThreatName"),
                                                              "path": d.get("Path"), "event_id": eid}}
    if ch == SYSMON:
        attrs = {"event_id": eid, "sysmon": True}
        et = {1: "process_start", 3: "network_connect", 7: "image_load", 8: "process_access", 10: "process_access",
              11: "file_create", 22: "dns_query", 25: "process_tamper"}.get(eid)
        if eid == 4:
            return "sensor_tamper", {**base, "attributes": {"kind": "sysmon_state", "state": d.get("State"), "event_id": 4}}
        if eid == 16:
            return "sensor_tamper", {**base, "attributes": {"kind": "sysmon_config", "event_id": 16}}
        if eid in (12, 13, 14):
            tgt = d.get("TargetObject", "")
            attrs.update({"target": tgt, "details": d.get("Details"), "run_key": bool(RUN_KEY.search(tgt))})
            return "persistence_change", {**base, "attributes": attrs}
        if eid in (19, 20, 21):
            attrs["wmi"] = True
            return "windows_event", {**base, "attributes": attrs}
        if eid == 1:
            attrs.update({"command_line": d.get("CommandLine"), "parent_image": d.get("ParentImage"),
                          "hashes": d.get("Hashes"), "guid": d.get("ProcessGuid")})
        elif eid == 3:
            attrs.update({"remote": f"{d.get('DestinationIp')}:{d.get('DestinationPort')}", "proto": d.get("Protocol")})
        elif eid == 11:
            attrs.update({"target_file": d.get("TargetFilename")})
        elif eid == 22:
            attrs.update({"query": d.get("QueryName")})
        elif eid in (8, 10):
            attrs.update({"target_image": d.get("TargetImage"), "granted": d.get("GrantedAccess")})
        if et:
            return et, {**base, "attributes": attrs}
    return None


class WinEventCollector(Collector):
    name_id = "windows_events"
    interval = 10.0

    def setup(self):
        self.since = time.time() - 5
        caps = self.agent.caps["sources"]
        self.channels = []
        if caps.get("event_log_system", {}).get("status") == "available":
            self.channels.append("System")
        if caps.get("event_log_security", {}).get("status") == "available":
            self.channels.append("Security")
        if caps.get("sysmon", {}).get("status") in ("available",):
            self.channels.append(SYSMON)
        if caps.get("defender", {}).get("status") == "available":
            self.channels.append(DEFENDER)

    def query(self, channel: str, since: float) -> str:
        import datetime as dt
        iso = dt.datetime.fromtimestamp(since, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        ids = " or ".join(f"EventID={i}" for i in sorted(WANTED[channel]))
        q = f"*[System[({ids}) and TimeCreated[@SystemTime>='{iso}']]]"
        r = subprocess.run(["wevtutil", "qe", channel, f"/q:{q}", "/f:xml", "/c:300", "/rd:false"],
                           capture_output=True, text=True, timeout=20, creationflags=0x08000000)
        return r.stdout if r.returncode == 0 else ""

    def tick(self):
        a = self.agent
        if not config.IS_WINDOWS:
            return
        start = time.time()
        for ch in self.channels:
            for rec in parse_events(self.query(ch, self.since)):
                m = map_event(rec)
                if not m:
                    continue
                et, kw = m
                pid = kw.get("pid")
                pkey = next((k for k, v in a.procs.items() if v["pid"] == pid), None) if pid else None
                src = "sysmon" if ch == SYSMON else "windows_event"
                a.emit(src, et, process_key=pkey, **kw)
        self.since = start - 1     # overlap by 1 s; INSERT OR IGNORE + deterministic detection ids tolerate duplicates
