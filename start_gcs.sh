#!/usr/bin/env bash
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$ROOT_DIR/.venv/bin/activate" 2>/dev/null || true
python "$ROOT_DIR/run_proxy.py" --mode proxy --role gcs --public-host "$([ -f "$ROOT_DIR/project_ip_config.py" ] && python -c "import project_ip_config as p; print(p.GCS_HOST)")"
