#!/usr/bin/env bash
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$ROOT_DIR/.venv/bin/activate" 2>/dev/null || true
GCS_HOST=$(python -c "import project_ip_config as p; print(p.GCS_HOST)")
PUBLIC_HOST=$(python -c "import project_ip_config as p; print(p.DRONE_HOST)")
python "$ROOT_DIR/run_proxy.py" --mode benchmark --duration 30 --public-host "$PUBLIC_HOST" --gcs-host "$GCS_HOST"
