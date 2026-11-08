# Web UI

The web UI is a simple local dashboard served by `server/main.py`.

## Main screens
- Simulated agents
- Activity monitor
- Listener lab management
- Basic health and stats views

## Run
```powershell
python server/main.py
```
Then open `http://127.0.0.1:8000`.

## Notes
- The UI targets the defensive lab mode only
- Listener creation is localhost-only
- Tasking is disabled
