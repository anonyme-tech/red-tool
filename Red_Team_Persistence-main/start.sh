#!/bin/bash
set -e

echo "========================================"
echo "Defensive Listener Lab Launcher"
echo "========================================"

if ! command -v python3 &> /dev/null; then
    echo "Python3 not found. Please install Python 3.10+"
    exit 1
fi

echo "Python found"

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

if [ ! -f ".installed" ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
    touch .installed
fi

if [ ! -f ".env" ]; then
    echo "Copying .env.example..."
    cp .env.example .env
fi

echo ""
echo "1. Lab server"
echo "2. Heartbeat simulator"
echo "3. Listener CLI"
echo ""

read -p "Select option (1-3): " choice

case $choice in
    1)
        echo "Starting lab server..."
        cd server
        python main.py
        ;;
    2)
        echo "Starting heartbeat simulator..."
        cd agent
        python beacon.py --server http://127.0.0.1:8000 --listener listener_1
        ;;
    3)
        echo "Starting listener CLI..."
        cd server
        python listener_cli.py
        ;;
    *)
        echo "Invalid option"
        exit 1
        ;;
esac
