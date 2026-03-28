#!/usr/bin/env bash
set -euo pipefail

# Run from ~/ironclad_backend/app/

mkdir -p api/v1/endpoints
mkdir -p models
mkdir -p services
mkdir -p scanners
mkdir -p tests

# Root app files stay in place
# (main.py, config.py, logger.py, dependencies.py remain in app/)

# API layer
mv router.py        api/v1/router.py
mv health.py        api/v1/endpoints/health.py
mv payloads.py      api/v1/endpoints/payloads.py

# Models
mv common.py        models/common.py
mv payload.py       models/payload.py

# Services
mv payload_service.py services/payload_service.py

# Scanners
mv base_scanner.py  scanners/base_scanner.py

# __init__.py files
touch __init__.py
touch api/__init__.py
touch api/v1/__init__.py
touch api/v1/endpoints/__init__.py
touch models/__init__.py
touch services/__init__.py
touch scanners/__init__.py

echo "Structure restored. Ready for Gunicorn."
