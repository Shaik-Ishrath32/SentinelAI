# SentinelAI: Full-stack prototype (FastAPI + scikit-learn + SQLite + WebSocket)

Real-time enterprise threat detection and incident intelligence. All events are **simulated**; no real telemetry, IBM Z/LinuxONE integration or production claims are made.

## Run in VS Code
1. Install Python 3.10+ and open this folder in VS Code (File > Open Folder).
2. Open the terminal (Ctrl+`) and run:
   - Windows: `run.bat`
   - Mac/Linux: `./run.sh`
   (or manually: `cd backend && python -m venv .venv && .venv\Scripts\activate && pip install -r requirements.txt && uvicorn main:app --port 8000`)
3. Open http://localhost:8000. The header shows **LIVE BACKEND** when connected.
4. API docs: http://localhost:8000/docs. Stored history: /api/alerts and /api/audit.

If the backend is not running, `frontend/index.html` still works standalone (in-browser simulation).

## Architecture
```
Simulator (login, transaction, application, metric events)
  -> Detection: rules + scikit-learn IsolationForest (transactions) + z-score (metrics)
  -> Incident intelligence: correlation, risk score, explanation, playbook
  -> Controlled response: Analyst requests, Admin approves (enforced by the API, HTTP 403 otherwise), simulated remediation
  -> SQLite (alerts, audit) + WebSocket push to the dashboard every second
```

## Demo script
1. Click **Run labeled test suite** and open the Evaluation tab (precision, recall, FPR, latency, audit completeness).
2. Click **Full kill chain**: raw alerts become one Critical incident; point at the network map and Top threats.
3. As Analyst, request "block IP"; try to approve (blocked); switch to Admin and approve; show the 4-stage timeline and audit log.
4. Click **Fraud transaction** to show the Isolation Forest score and explanation.

## Honest limits
Synthetic data; the model trains on a synthetic baseline and results are prototype results on simulated scenarios. Not claimed: real log ingestion, Kafka, PostgreSQL (SQLite used), production deployment.
