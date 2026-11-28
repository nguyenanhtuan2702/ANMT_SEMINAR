"""UI-independent upload path used by Streamlit and end-to-end tests."""
import copy
import time

from detection.pipeline import run_detection_pipeline
from preprocessing.log_loader import load_logs
from preprocessing.log_normalizer import normalize


def run_upload_pipeline(source):
    started = time.perf_counter()
    loaded = load_logs(source)
    load_seconds = time.perf_counter()-started
    step = time.perf_counter()
    normalized = normalize(loaded)
    normalize_seconds = time.perf_counter()-step
    result = run_detection_pipeline(normalized)
    result["report"]["timings_seconds"].update(load=load_seconds, normalize=normalize_seconds,
                                             upload_total=time.perf_counter()-started)
    result["report"]["load"] = copy.deepcopy(loaded.attrs["load_report"])
    result["detected_logs"].attrs["pipeline_report"] = copy.deepcopy(result["report"])
    return result
