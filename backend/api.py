"""
backend/api.py
==============
ThreatScope Flask REST API.

Endpoints
---------
  GET  /api/health             — liveness check
  GET  /api/status             — pipeline + model status
  POST /api/analyse            — analyse a single feature vector
  POST /api/analyse/batch      — analyse multiple flows (JSON array)
  GET  /api/demo/stream        — SSE stream of demo events
  GET  /api/demo/replay        — trigger a full demo replay

Run
---
  python backend/api.py
  (or)
  python -m backend.api

Dashboard is served statically from dashboard/index.html.
"""

import os
import sys
import json
import time
import threading
import traceback
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import feature_schema as fs

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

DASHBOARD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dashboard"
)

app = Flask(__name__, static_folder=DASHBOARD_DIR, static_url_path="")
CORS(app)

# ---------------------------------------------------------------------------
# Lazy pipeline loader (loads once on first request)
# ---------------------------------------------------------------------------

_pipeline = None
_pipeline_lock = threading.Lock()
_pipeline_error = None


def _get_pipeline():
    global _pipeline, _pipeline_error
    if _pipeline is not None:
        return _pipeline
    with _pipeline_lock:
        if _pipeline is not None:
            return _pipeline
        try:
            from threatscope.pipeline import ThreatScopePipeline
            _pipeline = ThreatScopePipeline(require_xgb=False)
            _pipeline_error = None
            print("[API] Pipeline loaded successfully.")
        except Exception as e:
            _pipeline_error = str(e)
            print(f"[API] Pipeline load error: {e}")
    return _pipeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts():
    return datetime.now(timezone.utc).isoformat()


def _error(msg: str, code: int = 400):
    return jsonify({"error": msg, "timestamp": _ts()}), code


# ---------------------------------------------------------------------------
# Static dashboard
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(DASHBOARD_DIR, "index.html")


# ---------------------------------------------------------------------------
# Health / status
# ---------------------------------------------------------------------------

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": _ts()})


@app.route("/api/status")
def status():
    pipeline = _get_pipeline()
    models_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "models")

    return jsonify({
        "pipeline_ready":  pipeline is not None,
        "pipeline_error":  _pipeline_error,
        "xgb_available":   pipeline._xgb_available if pipeline else False,
        "if_threshold":    pipeline.if_threshold   if pipeline else None,
        "models_present": {
            "isolation_forest":    os.path.exists(os.path.join(models_dir, "isolation_forest.pkl")),
            "isolation_scaler":    os.path.exists(os.path.join(models_dir, "isolation_scaler.pkl")),
            "isolation_threshold": os.path.exists(os.path.join(models_dir, "isolation_threshold.txt")),
            "xgb_classifier":      os.path.exists(os.path.join(models_dir, "xgb_classifier.pkl")),
            "xgb_label_encoder":   os.path.exists(os.path.join(models_dir, "xgb_label_encoder.pkl")),
        },
        "feature_schema": fs.FEATURES,
        "timestamp": _ts(),
    })


# ---------------------------------------------------------------------------
# Single-flow analysis
# ---------------------------------------------------------------------------

@app.route("/api/analyse", methods=["POST"])
def analyse():
    pipeline = _get_pipeline()
    if pipeline is None:
        return _error(f"Pipeline not ready: {_pipeline_error}", 503)

    data = request.get_json(silent=True)
    if not data:
        return _error("Request body must be JSON with feature values.")

    # Accept both flat dict and wrapped {"features": {...}}
    features = data.get("features", data)

    missing = [f for f in fs.FEATURES if f not in features]
    if missing:
        return _error(f"Missing features: {missing}")

    try:
        import pandas as pd
        row_df = pd.DataFrame([features])[fs.FEATURES]
        result = pipeline.run_df(row_df)[0]
        result["timestamp"] = _ts()
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return _error(f"Analysis failed: {str(e)}", 500)


# ---------------------------------------------------------------------------
# Batch analysis
# ---------------------------------------------------------------------------

@app.route("/api/analyse/batch", methods=["POST"])
def analyse_batch():
    pipeline = _get_pipeline()
    if pipeline is None:
        return _error(f"Pipeline not ready: {_pipeline_error}", 503)

    data = request.get_json(silent=True)
    if not data or not isinstance(data, list):
        return _error("Request body must be a JSON array of flow objects.")

    if len(data) > 1000:
        return _error("Batch size limit is 1000 flows per request.")

    try:
        import pandas as pd
        df = pd.DataFrame(data)[fs.FEATURES]
        results = pipeline.run_df(df)
        ts = _ts()
        for r in results:
            r["timestamp"] = ts
        return jsonify({"count": len(results), "results": results})
    except Exception as e:
        traceback.print_exc()
        return _error(f"Batch analysis failed: {str(e)}", 500)


# ---------------------------------------------------------------------------
# Demo replay (SSE stream)
# ---------------------------------------------------------------------------

# Import demo scenarios (defined below)
def _load_demo_scenarios():
    demo_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "demo", "scenarios.json"
    )
    if os.path.exists(demo_path):
        with open(demo_path) as fh:
            return json.load(fh)
    return []


@app.route("/api/demo/stream")
def demo_stream():
    """
    Server-Sent Events stream for demo replay.
    Client connects and receives flow analysis events with simulated delays.
    """
    pipeline = _get_pipeline()
    if pipeline is None:
        return _error(f"Pipeline not ready: {_pipeline_error}", 503)

    scenarios = _load_demo_scenarios()
    if not scenarios:
        return _error("No demo scenarios found. Run demo/generate_scenarios.py first.", 503)

    def event_generator():
        import pandas as pd

        # Send initial connected event
        yield f"data: {json.dumps({'event': 'connected', 'timestamp': _ts()})}\n\n"

        for i, scenario in enumerate(scenarios):
            time.sleep(scenario.get("delay_seconds", 1.5))

            features = {k: scenario[k] for k in fs.FEATURES}
            try:
                df = pd.DataFrame([features])[fs.FEATURES]
                result = pipeline.run_df(df)[0]
                result["timestamp"] = _ts()
                result["scenario_id"] = i
                result["scenario_name"] = scenario.get("name", f"Flow {i+1}")
                result["source_ip"] = scenario.get("source_ip", "192.168.x.x")
                result["dest_ip"]   = scenario.get("dest_ip",   "10.0.x.x")
                yield f"data: {json.dumps(result)}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'event': 'error', 'message': str(e)})}\n\n"

        yield f"data: {json.dumps({'event': 'replay_complete', 'timestamp': _ts()})}\n\n"

    return Response(
        event_generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/api/demo/scenarios")
def demo_scenarios_list():
    """Return the list of available demo scenarios (metadata only)."""
    scenarios = _load_demo_scenarios()
    meta = [
        {
            "id":   i,
            "name": s.get("name", f"Flow {i+1}"),
            "expected_label": s.get("expected_label", "Unknown"),
            "description": s.get("description", ""),
        }
        for i, s in enumerate(scenarios)
    ]
    return jsonify({"count": len(meta), "scenarios": meta})

# ---------------------------------------------------------------------------
# Live Monitoring (SSE stream)
# ---------------------------------------------------------------------------

@app.route("/api/live/stream")
def live_stream():
    """
    Server-Sent Events stream for LIVE Zeek conn.log tailing.
    """
    pipeline = _get_pipeline()
    if pipeline is None:
        return _error(f"Pipeline not ready: {_pipeline_error}", 503)
        
    # In production, this would be read from env var or config
    live_log_path = os.environ.get("ZEEK_CONN_LOG", os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "demo", "live_conn.log"
    ))
    
    # Create the file if it doesn't exist just for the tailer to not crash
    if not os.path.exists(live_log_path):
        os.makedirs(os.path.dirname(live_log_path), exist_ok=True)
        with open(live_log_path, 'a') as f:
            f.write("#fields\\tts\\tuid\\tid.orig_h\\tid.orig_p\\tid.resp_h\\tid.resp_p\\tproto\\tservice\\tduration\\torig_bytes\\tresp_bytes\\tconn_state\\tlocal_orig\\tlocal_resp\\tmissed_bytes\\thistory\\torig_pkts\\torig_ip_bytes\\tresp_pkts\\tresp_ip_bytes\\ttunnel_parents\n")

    def live_event_generator():
        from threatscope.zeek_extractor import parse_single_line
        import pandas as pd
        
        yield f"data: {json.dumps({'event': 'connected', 'timestamp': _ts(), 'message': f'Tailing {live_log_path}'})}\n\n"
        
        with open(live_log_path, "r", encoding="utf-8") as f:
            # Read header first if it exists
            header = []
            for line in f:
                if line.startswith("#fields"):
                    header = line.rstrip("\\n").split("\\t")[1:]
                    break
            
            # If no header found, use a default fallback header for the mock
            if not header:
                 header = ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","local_orig","local_resp","missed_bytes","history","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes","tunnel_parents"]
            
            # Seek to end of file to only process NEW lines
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                    
                line = line.rstrip("\\n")
                if not line or line.startswith("#"):
                    continue
                
                # Parse the TSV line
                features = parse_single_line(line, header)
                if not features:
                    continue # Invalid or missing data
                    
                # Extract some extra metadata for the UI if present
                fields = line.split("\\t")
                row_dict = dict(zip(header, fields))
                src_ip = row_dict.get("id.orig_h", "Unknown")
                dst_ip = row_dict.get("id.resp_h", "Unknown")
                
                try:
                    df = pd.DataFrame([features])[fs.FEATURES]
                    result = pipeline.run_df(df)[0]
                    result["timestamp"] = _ts()
                    result["scenario_name"] = "Live Traffic"
                    result["source_ip"] = src_ip
                    result["dest_ip"] = dst_ip
                    yield f"data: {json.dumps(result)}\n\n"
                except Exception as e:
                    print(f"Error processing live line: {e}")
                    pass

    return Response(
        live_event_generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("ThreatScope API Server")
    print("=" * 55)
    print(f"  Dashboard : http://127.0.0.1:5000/")
    print(f"  API Base  : http://127.0.0.1:5000/api/")
    print(f"  Health    : http://127.0.0.1:5000/api/health")
    print("=" * 55)

    # Pre-load pipeline
    _get_pipeline()

    app.run(debug=False, host="127.0.0.1", port=5000, threaded=True)
