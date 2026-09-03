#!/data/data/com.termux/files/usr/bin/bash
# CyberLab — start script for Termux / Linux
# Usage: bash start.sh

cd "$(dirname "$0")"

echo ""
echo "  Testnit CyberLab Security Intelligence Platform"
echo "  ──────────────────────────────────────────"
echo ""

# Install deps if needed
if ! python3 -c "import flask,requests" 2>/dev/null; then
  echo "  Installing dependencies..."
  pip install -r requirements.txt --break-system-packages -q
fi

# Open browser if possible
if command -v xdg-open &>/dev/null; then
  sleep 1.5 && xdg-open http://localhost:5050 &
elif command -v termux-open-url &>/dev/null; then
  sleep 2 && termux-open-url http://localhost:5050 &
fi

echo "  Running on → http://localhost:5050"
echo "  Press Ctrl+C to stop"
echo ""
python3 app.py
