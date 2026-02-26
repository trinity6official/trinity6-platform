#!/bin/bash
echo "Setting up Trinity6 Platform Backend..."
pip install -r requirements.txt
mkdir -p data/scans
export TRINITY6_ADMIN_SECRET="change_this_to_something_secret"
echo "Setup complete."
echo "Run: uvicorn api:app --host 0.0.0.0 --port 8000"
