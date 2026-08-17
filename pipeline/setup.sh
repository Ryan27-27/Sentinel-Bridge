#!/usr/bin/env bash
# setup.sh — one-command bootstrap for AppSec Pipeline Sentinel
set -e

echo "Setting up AppSec Pipeline Sentinel..."

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is required but not installed."
    exit 1
fi

python3 -m pip install -r requirements.txt --quiet
chmod +x sentinel.py

echo ""
echo "✓ Setup complete!"
echo ""
if command -v ffuf &> /dev/null; then
    echo "✓ ffuf detected — route discovery will use real fuzzing"
else
    echo "ℹ ffuf not found — route discovery will use a slower built-in fallback."
    echo "  Install ffuf for full speed: go install github.com/ffuf/ffuf/v2@latest"
fi
echo ""
echo "Try it out:"
echo "  python3 sentinel.py status"
echo "  python3 sentinel.py demo"
echo "  python3 sentinel.py scan scanner/test_fixtures --type all"
echo "  python3 sentinel.py discover http://127.0.0.1:5050"
echo "  python3 sentinel.py vulns --severity critical"
echo "  python3 sentinel.py dashboard --type full"
echo "  python3 sentinel.py automate --dry-run"
echo ""
echo "Docker:"
echo "  docker build -t appsec-sentinel ."
echo "  docker run --rm appsec-sentinel status"
