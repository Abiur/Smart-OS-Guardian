"use strict";
G.apps.models = {
  name: "Model Lab", short: "models", icon: "model", w: 760, h: 520, title: h => `guardian@${h}: ~/models`,
  mount(body) {
    (async () => {
      const m = await api("/models"), h = G.state.health || await api("/health");
      const a = m.active;
      clear(body).append(el("div", { class: "pad" },
        el("h3", {}, "Installed models"),
        a ? kv([["model", a.model_id], ["version", a.version], ["feature schema", a.feature_schema_version], ["sha256", fmt.short(a.hash, 32)], ["high threshold", a.threshold_high], ["calibrated", a.calibrated ? "yes" : "no"], ["trained on", a.trained_on || "—"], ["metrics", JSON.stringify(a.metrics)]])
          : el("div", {}, el("div", { class: "note info" }, el("b", {}, "No PE malware model installed — awaiting dataset. "), "Guardian runs in rules + correlation mode. E1 (PE score) evidence is unavailable and every incident says so."),
            el("div", { class: "card" }, el("h4", {}, "How to add the model (when the dataset is ready)"), el("ol", { style: "margin:0;padding-left:20px" },
              el("li", {}, "Place EMBER data under ai/malware-pe/data/ (see ai/malware-pe/README.md)."), el("li", {}, "Run  train_run.bat  (or python ai/malware-pe/train.py)."),
              el("li", {}, "The package is written to ai/model-registry/malware-pe/<version>/ with model card, hash and calibrator."), el("li", {}, "Restart Guardian. If hash or feature schema mismatch, the model is refused and rules-only continues.")))),
        m.warning ? el("div", { class: "note" }, m.warning) : null,
        el("h3", { style: "margin-top:14px" }, "Live feature extractor"), kv([["schema", m.extractor_schema]]),
        el("div", { class: "dim", style: "margin-top:10px" }, m.note),
        m.installed.length ? table([{ k: "model_id", label: "MODEL" }, { k: "version", label: "VERSION" }, { k: "status", label: "STATUS" }], m.installed) : null));
    })().catch(e => body.append(el("div", { class: "pad st-bad" }, e.message)));
  },
};

G.apps.settings = {
  name: "Settings & Privacy", short: "cfg", icon: "cfg", w: 820, h: 620, title: h => `guardian@${h}: ~/settings`,
  mount(body) {
    let alive = true;
    async function draw() {
      const [p, al, au, h] = await Promise.all([api("/settings/privacy"), api("/allowlist"), api("/audit?limit=30"), api("/health")]);
      const tog = (k, label, note) => el("label", { style: "display:flex;gap:8px;margin:4px 0", title: note }, el("input", { type: "checkbox", checked: p[k], onchange: async e => { await api("/settings/privacy", { method: "PUT", body: { [k]: e.target.checked } }); toast(`${k} = ${e.target.checked} (collector changes apply after restart)`); } }), label);
      clear(body).append(el("div", { class: "pad" },
        el("h3", {}, "Privacy & telemetry"),
        el("div", { class: "card" }, tog("store_command_lines", "Store command lines (secrets are always redacted)"), tog("redact_paths", "Redact user names in paths"), tog("collect_network", "Collect connection metadata"), tog("collect_registry", "Watch startup (Run) keys"),
          el("label", {}, "Raw event retention (days) ", el("input", { type: "number", min: 1, max: 90, value: p.retention_days_events, style: "width:70px", onchange: async e => { await api("/settings/privacy", { method: "PUT", body: { retention_days_events: +e.target.value } }); } })),
          el("div", { class: "dim", style: "margin-top:6px" }, "Cloud sync: OFF — not implemented in the MVP. Nothing leaves this machine. No documents, browser content or keystrokes are ever collected.")),
        el("h3", { style: "margin-top:14px" }, "Telemetry sources"),
        table([{ label: "SOURCE", render: r => r[0] }, { label: "STATE", render: r => el("span", { class: statusCls(r[1].status) }, statusMark(r[1].status) + " " + r[1].status) }, { label: "DETAIL", render: r => fmt.short(r[1].reason, 90) }], Object.entries(h.sources)),
        el("h3", { style: "margin-top:14px" }, "Allowlist"),
        al.items.length ? table([{ k: "kind", label: "KIND" }, { label: "VALUE", render: r => fmt.short(r.value, 60) }, { k: "reason", label: "REASON" }, { label: "", render: r => el("button", { onclick: async () => { await api(`/allowlist?kind=${r.kind}&value=${encodeURIComponent(r.value)}`, { method: "DELETE" }); draw(); } }, "remove") }], al.items) : el("div", { class: "dim" }, "empty"),
        el("h3", { style: "margin-top:14px" }, "Your data"),
        el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" },
          el("button", { onclick: async () => download("guardian_export.json", await api("/export")) }, "export investigations (json)"),
          el("button", { onclick: async () => { await api("/collection", { method: "POST", body: { paused: !h.paused } }); toast(h.paused ? "resumed" : "paused"); draw(); } }, h.paused ? "resume collection" : "pause collection"),
          el("button", { class: "danger", onclick: async () => { if (prompt("This deletes all local events, detections and incidents. Type DELETE to confirm:") !== "DELETE") return; await api("/data", { method: "DELETE", body: { confirm: "DELETE" } }); toast("local telemetry deleted"); } }, "delete local data…")),
        el("h3", { style: "margin-top:14px" }, `Audit log  ${au.chain_ok ? "(hash chain verified ✔)" : "(CHAIN BROKEN ✖)"}`),
        table([{ label: "TIME", render: r => fmt.datetime(r.ts) }, { k: "actor", label: "ACTOR" }, { k: "action", label: "ACTION" }, { label: "TARGET", render: r => fmt.short(r.target, 40) }, { k: "result", label: "RESULT" }], au.items.slice(0, 15)),
        el("div", { class: "dim", style: "margin-top:12px" }, `Smart OS Guardian ${h.version} · API loopback only · session token rotates at each start · data: ${h.db.path}`)));
    }
    draw().catch(() => { }); return { destroy() { alive = false; } };
  },
};
