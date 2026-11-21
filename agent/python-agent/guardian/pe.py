"""PE static analysis + model slot. Files are parsed, never executed.

Model contract (spec 11.2): every result carries model_id, model_version, feature_schema_version, score, threshold,
inference_time_ms. With no model installed the scan reports metadata only and the system runs rules-only.
"""
from __future__ import annotations
import hashlib, json, math, time, pathlib, os
from . import config

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

FEATURE_SCHEMA = "guardian_pe_v1"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def extract_metadata(path: str) -> dict:
    """Light, safe metadata. The EMBER-compatible feature vector is built in ai/malware-pe/features.py."""
    p = pathlib.Path(path)
    out: dict = {"path": str(p), "exists": p.is_file()}
    if not p.is_file():
        return out
    st = p.stat()
    out["size"] = st.st_size
    h = hashlib.sha256()
    with open(p, "rb") as f:
        head = f.read(2)
        f.seek(0)
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    out["sha256"] = h.hexdigest()
    out["is_pe"] = head == b"MZ"
    if out["is_pe"] and pefile and st.st_size < 256 * 1024 * 1024:
        try:
            pe = pefile.PE(str(p), fast_load=False)
            secs = []
            for s in pe.sections:
                data = s.get_data()
                secs.append({"name": s.Name.rstrip(b"\x00").decode("latin1", "replace"), "vsize": s.Misc_VirtualSize,
                             "rsize": s.SizeOfRawData, "entropy": round(entropy(data[:2_000_000]), 2),
                             "exec": bool(s.Characteristics & 0x20000000), "write": bool(s.Characteristics & 0x80000000)})
            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                imports = [e.dll.decode("latin1", "replace").lower() for e in pe.DIRECTORY_ENTRY_IMPORT][:60]
            out.update({"machine": hex(pe.FILE_HEADER.Machine), "timestamp": pe.FILE_HEADER.TimeDateStamp,
                        "is_dll": pe.is_dll(), "subsystem": getattr(pe.OPTIONAL_HEADER, "Subsystem", None),
                        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "sections": secs, "imports": imports,
                        "has_signature_dir": bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size),
                        "high_entropy_sections": [s["name"] for s in secs if s["entropy"] > 7.2],
                        "wx_sections": [s["name"] for s in secs if s["exec"] and s["write"]]})
            pe.close()
        except Exception as e:
            out["parse_error"] = str(e)[:200]
    return out


class PEModel:
    """Loads a LightGBM model package from ai/model-registry/<model_id>/<version>/ if present.

    Package layout: model.txt (LightGBM text model), calibrator.json, model_card.json, feature_schema.json.
    Mismatch of feature schema / hash -> model is NOT loaded; system continues rules-only (spec 10.4, 8.2).
    """

    def __init__(self):
        self.loaded = False
        self.info: dict = {}
        self.booster = None
        self.calibrator = None
        self.warning: str | None = None
        self._try_load()

    def _try_load(self):
        root = config.MODEL_DIR / "malware-pe"
        if not root.exists():
            return
        versions = sorted([d for d in root.iterdir() if d.is_dir()])
        if not versions:
            return
        d = versions[-1]
        try:
            card = json.loads((d / "model_card.json").read_text())
            mpath = d / "model.txt"
            digest = hashlib.sha256(mpath.read_bytes()).hexdigest()
            if card.get("model_sha256") != digest:
                self.warning = "model hash mismatch: model not loaded, running rules-only"
                return
            if card.get("feature_schema_version") != self._extractor_schema():
                self.warning = "feature schema mismatch: model not loaded, running rules-only"
                return
            import lightgbm as lgb
            self.booster = lgb.Booster(model_file=str(mpath))
            cal = d / "calibrator.json"
            self.calibrator = json.loads(cal.read_text()) if cal.exists() else None
            self.info = {"model_id": card.get("model_id", "malware-pe"), "version": card.get("version", d.name), "hash": digest,
                         "feature_schema_version": card["feature_schema_version"], "threshold_high": card.get("threshold_high", 0.9),
                         "metrics": card.get("metrics", {}), "trained_on": card.get("dataset"), "calibrated": bool(self.calibrator)}
            self.loaded = True
        except Exception as e:
            self.warning = f"model load failed: {e}"

    @staticmethod
    def _extractor_schema() -> str:
        try:
            import sys
            sys.path.insert(0, str(config.ROOT / "ai" / "malware-pe"))
            import features  # type: ignore
            return features.FEATURE_SCHEMA_VERSION
        except Exception:
            return "unavailable"

    def score_file(self, path: str) -> dict | None:
        if not self.loaded:
            return None
        import sys
        sys.path.insert(0, str(config.ROOT / "ai" / "malware-pe"))
        import features  # type: ignore
        t0 = time.perf_counter()
        vec = features.vectorize_file(path)
        raw = float(self.booster.predict([vec])[0])
        score = self._calibrate(raw)
        return {"model_id": self.info["model_id"], "model_version": self.info["version"],
                "feature_schema_version": self.info["feature_schema_version"], "score": round(score, 4), "raw_score": round(raw, 4),
                "threshold": self.info["threshold_high"], "prediction": "malicious" if score >= self.info["threshold_high"] else "benign",
                "calibrated": bool(self.calibrator), "inference_time_ms": round((time.perf_counter() - t0) * 1000, 1)}

    def _calibrate(self, p: float) -> float:
        if not self.calibrator:
            return p
        xs, ys = self.calibrator["x"], self.calibrator["y"]      # isotonic step function
        if p <= xs[0]:
            return ys[0]
        for i in range(1, len(xs)):
            if p <= xs[i]:
                return ys[i]
        return ys[-1]


def scan_file(path: str, model: PEModel) -> dict:
    meta = extract_metadata(path)
    res = {"file": meta, "model": model.score_file(path) if meta.get("is_pe") else None, "executed": False}
    res["model_status"] = "scored" if res["model"] else ("no model installed (awaiting dataset)" if not model.loaded else "not a PE file")
    if model.warning:
        res["warning"] = model.warning
    return res
