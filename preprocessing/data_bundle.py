from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
BUNDLE_DIR = PROJECT_DIR / "data" / "processed"


def verify_bundle(base_dir: str | Path | None = None) -> list[str]:
    base = Path(base_dir) if base_dir is not None else BUNDLE_DIR
    manifest = json.loads((base/"MANIFEST.json").read_text(encoding="utf-8"))
    checked = []
    for name, spec in manifest["files"].items():
        path = base/name
        if not path.is_file():
            raise FileNotFoundError(f"Missing bundle file: {path}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != spec["sha256"]:
            raise ValueError(f"Checksum mismatch: {path}")
        checked.append(name)
    return checked


def load_table(filename: str = "normalized_logs.csv", *, base_dir: str | Path | None = None) -> pd.DataFrame:
    base = Path(base_dir) if base_dir is not None else BUNDLE_DIR
    path = base/filename
    metadata = json.loads(path.with_suffix(".schema.json").read_text(encoding="utf-8"))
    version = metadata.get("format_version")
    if version not in {"spedia.normalized_csv.v1", "spedia.shared_outputs.v1"}:
        raise ValueError(f"Unsupported CSV transport version: {version}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != metadata["csv_sha256"]:
        raise ValueError(f"Checksum mismatch: {path}")
    frame = pd.read_csv(path, encoding=metadata["encoding"], dtype="string",
                        keep_default_na=False, na_values=[metadata["null_marker"]], skip_blank_lines=False)
    if version == "spedia.normalized_csv.v1":
        specs = metadata["columns"]
    else:
        specs = []
        for name in metadata["columns"]:
            dtype = metadata["dtypes"][name]
            kind = ("json" if name in metadata["json_columns"] else
                    "datetime" if dtype.startswith("datetime64[") else
                    "numeric" if dtype in {"int64", "Int64"} else "text")
            specs.append({"name": name, "kind": kind, "pandas_dtype": dtype})
    if frame.columns.tolist() != [s["name"] for s in specs] or len(frame) != metadata["row_count"]:
        raise ValueError("CSV columns/row count do not match the sidecar.")
    for spec in specs:
        name, kind, dtype = spec["name"], spec["kind"], spec["pandas_dtype"]
        values = frame[name]
        if kind == "datetime":
            frame[name] = pd.to_datetime(values, format="%Y-%m-%d %H:%M:%S.%f", errors="raise").astype(dtype)
        elif kind == "date":
            frame[name] = pd.to_datetime(values, format="%Y-%m-%d", errors="raise").dt.date
        elif kind == "numeric":
            frame[name] = pd.to_numeric(values, errors="raise").astype(dtype)
        elif kind == "boolean":
            if not values.dropna().isin(["True", "False"]).all():
                raise ValueError(f"Invalid boolean values in {name}.")
            frame[name] = values.map({"True": True, "False": False}).astype(dtype)
        elif kind == "json":
            frame[name] = values.map(json.loads).astype(object)
        elif kind in {"string", "object_string", "text"}:
            # pandas 3's 'str' dtype has no identical nullable alias in pandas 2.
            frame[name] = values.astype("string" if dtype == "str" else dtype)
        else:
            raise ValueError(f"Unsupported column kind: {name}/{kind}")
    frame.attrs = copy.deepcopy(metadata["attrs"])
    if frame.attrs.get("detection_schema_version") == "spedia.detected.v1":
        frame["rule_ids"] = frame.rule_ids.map(json.loads).astype(object)
        if not frame.rule_ids.str.len().eq(frame.alert_count).all():
            raise ValueError("alert_count does not match the current event's rule_ids.")
    if "source_row_id" in frame and metadata.get("kind") != "atomic_alerts":
        if frame.source_row_id.isna().any() or frame.source_row_id.duplicated().any():
            raise ValueError("Event-level source_row_id values must be unique and nonmissing.")
    return frame
