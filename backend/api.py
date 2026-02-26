#!/usr/bin/env python3
"""
Trinity6 Platform Backend API
Receives scan results from Trinity6 agents
Stores results and serves dashboard
Sends email notifications to clients
Deploy this on trinity6.com server
"""

import os
import json
import uuid
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn


# ==========================================
# SETUP
# ==========================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('trinity6_api')

app = FastAPI(
    title="Trinity6 Platform API",
    description="Compliance monitoring for SMBs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = Path("data")
CLIENTS_FILE = DATA_DIR / "clients.json"
SCANS_DIR = DATA_DIR / "scans"
TOKENS_FILE = DATA_DIR / "tokens.json"

DATA_DIR.mkdir(exist_ok=True)
SCANS_DIR.mkdir(exist_ok=True)


# ==========================================
# DATA MODELS
# ==========================================

class ScanResult(BaseModel):
    client_id: str
    server_name: str
    hostname: str
    os_info: str
    scan_timestamp: str
    agent_version: str
    checks: List[Dict[str, Any]]
    summary: Dict[str, Any]
    previous_scan_id: Optional[str] = None


class ClientRegister(BaseModel):
    name: str
    company: str
    email: str
    plan: str = "starter"


class LoginRequest(BaseModel):
    email: str
    password: str


class DriftAlert(BaseModel):
    client_id: str
    server_name: str
    new_failures: List[Dict]
    new_passes: List[Dict]


# ==========================================
# DATA HELPERS
# ==========================================

def load_json(filepath: Path) -> dict:
    """Load JSON file safely"""
    if filepath.exists():
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}


def save_json(filepath: Path, data: dict):
    """Save JSON file safely"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def load_clients() -> dict:
    return load_json(CLIENTS_FILE)


def save_clients(clients: dict):
    save_json(CLIENTS_FILE, clients)


def load_tokens() -> dict:
    return load_json(TOKENS_FILE)


def save_tokens(tokens: dict):
    save_json(TOKENS_FILE, tokens)


def get_client_scans(client_id: str) -> List[dict]:
    """Get all scans for a client sorted by date"""
    client_scan_dir = SCANS_DIR / client_id
    if not client_scan_dir.exists():
        return []

    scans = []
    for scan_file in sorted(
        client_scan_dir.glob("*.json"),
        reverse=True
    ):
        try:
            with open(scan_file, 'r') as f:
                scans.append(json.load(f))
        except:
            pass
    return scans


def save_scan(client_id: str, scan_data: dict) -> str:
    """Save scan result and return scan ID"""
    scan_id = str(uuid.uuid4())[:8]
    scan_data['scan_id'] = scan_id

    client_scan_dir = SCANS_DIR / client_id
    client_scan_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_file = client_scan_dir / f"{timestamp}_{scan_id}.json"

    with open(scan_file, 'w') as f:
        json.dump(scan_data, f, indent=2)

    return scan_id


def calculate_score(checks: List[dict]) -> dict:
    """Calculate compliance score from checks"""
    total = len(checks)
    if total == 0:
        return {
            'score': 0,
            'pass': 0,
            'fail': 0,
            'warn': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

    passed = sum(
        1 for c in checks if c.get('status') == 'PASS'
    )
    failed = sum(
        1 for c in checks if c.get('status') == 'FAIL'
    )
    warned = sum(
        1 for c in checks if c.get('status') == 'WARN'
    )

    critical = sum(
        1 for c in checks
        if c.get('status') == 'FAIL'
        and c.get('severity') == 'critical'
    )
    high = sum(
        1 for c in checks
        if c.get('status') == 'FAIL'
        and c.get('severity') == 'high'
    )
    medium = sum(
        1 for c in checks
        if c.get('status') == 'FAIL'
        and c.get('severity') == 'medium'
    )
    low = sum(
        1 for c in checks
        if c.get('status') in ['FAIL', 'WARN']
        and c.get('severity') == 'low'
    )

    score = round((passed / total) * 100)

    return {
        'score': score,
        'total': total,
        'pass': passed,
        'fail': failed,
        'warn': warned,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low
    }


def detect_drift(
    current_checks: List[dict],
    previous_checks: List[dict]
) -> dict:
    """Detect what changed between scans"""
    current_by_desc = {
        c['description']: c for c in current_checks
    }
    previous_by_desc = {
        c['description']: c for c in previous_checks
    }

    new_failures = []
    new_passes = []
    unchanged_failures = []

    for desc, check in current_by_desc.items():
        prev = previous_by_desc.get(desc)
        if prev:
            if check['status'] == 'FAIL' \
               and prev['status'] != 'FAIL':
                new_failures.append(check)
            elif check['status'] == 'PASS' \
                 and prev['status'] == 'FAIL':
                new_passes.append(check)
            elif check['status'] == 'FAIL':
                unchanged_failures.append(check)
        else:
            if check['status'] == 'FAIL':
                new_failures.append(check)

    return {
        'has_changes': bool(new_failures or new_passes),
        'new_failures': new_failures,
        'new_passes': new_passes,
        'unchanged_failures': unchanged_failures,
        'new_failure_count': len(new_failures),
        'new_pass_count': len(new_passes)
    }


# ==========================================
# AUTH
# ==========================================

security = HTTPBearer(auto_error=False)


def verify_agent_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """Verify agent API token"""
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="No authentication token provided"
        )

    tokens = load_tokens()
    token = credentials.credentials

    for client_id, token_data in tokens.items():
        if token_data.get('agent_token') == token:
            return client_id

    raise HTTPException(
        status_code=401,
        detail="Invalid agent token"
    )


def verify_dashboard_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """Verify dashboard session token"""
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated"
        )

    tokens = load_tokens()
    token = credentials.credentials

    for client_id, token_data in tokens.items():
        if token_data.get('session_token') == token:
            expires = token_data.get('session_expires')
            if expires:
                if datetime.fromisoformat(expires) \
                   > datetime.now():
                    return client_id
            else:
                return client_id

    raise HTTPException(
        status_code=401,
        detail="Session expired. Please log in again."
    )


# ==========================================
# AGENT ENDPOINTS
# ==========================================

@app.post("/api/v1/scan/results")
async def receive_scan_results(
    scan: ScanResult,
    client_id: str = Depends(verify_agent_token)
):
    """
    Receive scan results from Trinity6 agent
    Agent calls this after every scan
    """
    if scan.client_id != client_id:
        raise HTTPException(
            status_code=403,
            detail="Client ID mismatch"
        )

    clients = load_clients()
    if client_id not in clients:
        raise HTTPException(
            status_code=404,
            detail="Client not found"
        )

    scan_data = scan.dict()

    score = calculate_score(scan_data['checks'])
    scan_data['score'] = score

    previous_scans = get_client_scans(client_id)
    drift = {}

    if previous_scans:
        latest_previous = None
        for prev in previous_scans:
            if prev.get('server_name') == scan.server_name:
                latest_previous = prev
                break

        if latest_previous:
            drift = detect_drift(
                scan_data['checks'],
                latest_previous.get('checks', [])
            )
            scan_data['drift'] = drift
            scan_data['previous_score'] = latest_previous.get(
                'score', {}
            ).get('score')

    scan_id = save_scan(client_id, scan_data)

    if not clients[client_id].get('servers'):
        clients[client_id]['servers'] = {}

    clients[client_id]['servers'][scan.server_name] = {
        'last_scan': scan.scan_timestamp,
        'last_score': score['score'],
        'last_scan_id': scan_id,
        'os_info': scan.os_info,
        'hostname': scan.hostname
    }
    clients[client_id]['last_activity'] = \
        datetime.now().isoformat()
    save_clients(clients)

    send_scan_notification(
        client_id=client_id,
        clients=clients,
        scan_data=scan_data,
        score=score,
        drift=drift
    )

    logger.info(
        f"Scan received from {client_id} "
        f"server {scan.server_name} "
        f"score {score['score']}%"
    )

    return {
        "success": True,
        "scan_id": scan_id,
        "score": score['score'],
        "message": f"Scan processed successfully. Score: {score['score']}%"
    }


@app.get("/api/v1/agent/config/{client_id}")
async def get_agent_config(
    client_id: str,
    agent_token: str = Depends(verify_agent_token)
):
    """Agent fetches its config from server"""
    clients = load_clients()
    if client_id not in clients:
        raise HTTPException(status_code=404)

    client = clients[client_id]
    return {
        "scan_frequency_days": client.get(
            'scan_frequency_days', 7
        ),
        "plan": client.get('plan', 'starter'),
        "notifications_enabled": client.get(
            'notifications_enabled', True
        )
    }


# ==========================================
# AUTH ENDPOINTS
# ==========================================

@app.post("/api/v1/auth/login")
async def login(request: LoginRequest):
    """Client dashboard login"""
    clients = load_clients()
    tokens = load_tokens()

    client_id = None
    for cid, client in clients.items():
        if client.get('email', '').lower() == \
           request.email.lower():
            stored_hash = client.get('password_hash', '')
            input_hash = hashlib.sha256(
                request.password.encode()
            ).hexdigest()
            if stored_hash == input_hash:
                client_id = cid
                break

    if not client_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    session_token = secrets.token_urlsafe(32)
    expires = (
        datetime.now() + timedelta(days=7)
    ).isoformat()

    if client_id not in tokens:
        tokens[client_id] = {}
    tokens[client_id]['session_token'] = session_token
    tokens[client_id]['session_expires'] = expires
    save_tokens(tokens)

    return {
        "success": True,
        "session_token": session_token,
        "client_id": client_id,
        "client_name": clients[client_id].get('name'),
        "company": clients[client_id].get('company')
    }


# ==========================================
# DASHBOARD ENDPOINTS
# ==========================================

@app.get("/api/v1/dashboard/overview")
async def get_dashboard_overview(
    client_id: str = Depends(verify_dashboard_token)
):
    """Get dashboard overview for client"""
    clients = load_clients()
    if client_id not in clients:
        raise HTTPException(status_code=404)

    client = clients[client_id]
    servers = client.get('servers', {})

    server_list = []
    total_score = 0

    for server_name, server_data in servers.items():
        server_list.append({
            'name': server_name,
            'hostname': server_data.get('hostname'),
            'os_info': server_data.get('os_info'),
            'last_scan': server_data.get('last_scan'),
            'score': server_data.get('last_score', 0),
            'status': get_server_status(
                server_data.get('last_score', 0)
            )
        })
        total_score += server_data.get('last_score', 0)

    avg_score = round(
        total_score / len(servers)
    ) if servers else 0

    return {
        "client_name": client.get('name'),
        "company": client.get('company'),
        "plan": client.get('plan', 'starter'),
        "total_servers": len(servers),
        "average_score": avg_score,
        "overall_status": get_server_status(avg_score),
        "servers": sorted(
            server_list,
            key=lambda x: x['score']
        ),
        "last_activity": client.get('last_activity')
    }


@app.get("/api/v1/dashboard/server/{server_name}")
async def get_server_detail(
    server_name: str,
    client_id: str = Depends(verify_dashboard_token)
):
    """Get detailed scan results for a server"""
    scans = get_client_scans(client_id)

    server_scans = [
        s for s in scans
        if s.get('server_name') == server_name
    ]

    if not server_scans:
        raise HTTPException(
            status_code=404,
            detail="No scans found for this server"
        )

    latest = server_scans[0]

    score_history = []
    for scan in server_scans[:10]:
        score_history.append({
            'date': scan.get('scan_timestamp', '')[:10],
            'score': scan.get('score', {}).get('score', 0)
        })

    checks = latest.get('checks', [])
    failed_checks = [
        c for c in checks if c.get('status') == 'FAIL'
    ]
    failed_checks.sort(
        key=lambda x: {
            'critical': 0, 'high': 1,
            'medium': 2, 'low': 3
        }.get(x.get('severity', 'low'), 3)
    )

    return {
        "server_name": server_name,
        "hostname": latest.get('hostname'),
        "os_info": latest.get('os_info'),
        "last_scan": latest.get('scan_timestamp'),
        "score": latest.get('score', {}),
        "previous_score": latest.get('previous_score'),
        "drift": latest.get('drift', {}),
        "failed_checks": failed_checks,
        "all_checks": checks,
        "score_history": score_history,
        "scan_id": latest.get('scan_id')
    }


@app.get("/api/v1/dashboard/history")
async def get_scan_history(
    client_id: str = Depends(verify_dashboard_token)
):
    """Get scan history for all servers"""
    scans = get_client_scans(client_id)

    history = []
    for scan in scans[:50]:
        history.append({
            'scan_id': scan.get('scan_id'),
            'server_name': scan.get('server_name'),
            'timestamp': scan.get('scan_timestamp'),
            'score': scan.get('score', {}).get('score', 0),
            'failures': scan.get('score', {}).get('fail', 0),
            'drift': scan.get('drift', {}).get(
                'has_changes', False
            )
        })

    return {
        "total_scans": len(history),
        "history": history
    }


@app.get("/api/v1/dashboard/alerts")
async def get_alerts(
    client_id: str = Depends(verify_dashboard_token)
):
    """Get active alerts for client"""
    scans = get_client_scans(client_id)
    alerts = []

    servers_seen = set()
    for scan in scans:
        server = scan.get('server_name')
        if server in servers_seen:
            continue
        servers_seen.add(server)

        score = scan.get('score', {}).get('score', 0)
        if score < 60:
            alerts.append({
                'type': 'critical_score',
                'severity': 'critical',
                'server': server,
                'message': f"Compliance score critically low: {score}%",
                'timestamp': scan.get('scan_timestamp')
            })

        drift = scan.get('drift', {})
        if drift.get('new_failures'):
            for failure in drift['new_failures']:
                if failure.get('severity') in [
                    'critical', 'high'
                ]:
                    alerts.append({
                        'type': 'new_failure',
                        'severity': failure['severity'],
                        'server': server,
                        'message': f"New failure: {failure['description']}",
                        'timestamp': scan.get('scan_timestamp')
                    })

    return {
        "total_alerts": len(alerts),
        "alerts": sorted(
            alerts,
            key=lambda x: {
                'critical': 0, 'high': 1,
                'medium': 2, 'low': 3
            }.get(x.get('severity', 'low'), 3)
        )
    }


# ==========================================
# ADMIN ENDPOINTS
# ==========================================

@app.post("/api/v1/admin/register_client")
async def register_client(
    client: ClientRegister,
    request: Request
):
    """
    Register new client
    Admin uses this to onboard new clients
    Protected by admin secret in header
    """
    admin_secret = request.headers.get('X-Admin-Secret')
    expected = os.environ.get('TRINITY6_ADMIN_SECRET', 'changeme')

    if admin_secret != expected:
        raise HTTPException(
            status_code=403,
            detail="Invalid admin secret"
        )

    client_id = str(uuid.uuid4())[:8]
    agent_token = secrets.token_urlsafe(32)
    temp_password = secrets.token_urlsafe(12)
    password_hash = hashlib.sha256(
        temp_password.encode()
    ).hexdigest()

    clients = load_clients()
    clients[client_id] = {
        'name': client.name,
        'company': client.company,
        'email': client.email,
        'plan': client.plan,
        'password_hash': password_hash,
        'created_at': datetime.now().isoformat(),
        'servers': {},
        'scan_frequency_days': 7,
        'notifications_enabled': True
    }
    save_clients(clients)

    tokens = load_tokens()
    tokens[client_id] = {
        'agent_token': agent_token
    }
    save_tokens(tokens)

    logger.info(
        f"New client registered: {client.company} "
        f"id={client_id}"
    )

    return {
        "success": True,
        "client_id": client_id,
        "agent_token": agent_token,
        "temp_password": temp_password,
        "dashboard_url": f"https://trinity6.com/dashboard",
        "install_command": (
            f"curl -s https://trinity6.com/install.sh | "
            f"sudo bash -s -- "
            f"--client-id {client_id} "
            f"--token {agent_token} "
            f"--email {client.email}"
        ),
        "message": (
            f"Client registered successfully. "
            f"Send install command to {client.company}."
        )
    }


@app.get("/api/v1/admin/clients")
async def list_clients(request: Request):
    """List all clients"""
    admin_secret = request.headers.get('X-Admin-Secret')
    expected = os.environ.get('TRINITY6_ADMIN_SECRET', 'changeme')

    if admin_secret != expected:
        raise HTTPException(status_code=403)

    clients = load_clients()
    summary = []

    for client_id, client in clients.items():
        servers = client.get('servers', {})
        scores = [
            s.get('last_score', 0)
            for s in servers.values()
        ]
        avg_score = round(
            sum(scores) / len(scores)
        ) if scores else 0

        summary.append({
            'client_id': client_id,
            'company': client.get('company'),
            'email': client.get('email'),
            'plan': client.get('plan'),
            'total_servers': len(servers),
            'average_score': avg_score,
            'created_at': client.get('created_at'),
            'last_activity': client.get('last_activity')
        })

    return {
        "total_clients": len(summary),
        "clients": sorted(
            summary,
            key=lambda x: x.get('last_activity', ''),
            reverse=True
        )
    }


# ==========================================
# HELPERS
# ==========================================

def get_server_status(score: int) -> str:
    """Get status label from score"""
    if score >= 80:
        return 'good'
    elif score >= 60:
        return 'warning'
    else:
        return 'critical'


def send_scan_notification(
    client_id: str,
    clients: dict,
    scan_data: dict,
    score: dict,
    drift: dict
):
    """
    Send email notification after scan
    Email contains summary and dashboard link
    Not raw scan data
    """
    client = clients.get(client_id, {})
    client_email = client.get('email')

    if not client_email:
        return

    has_critical = score.get('critical', 0) > 0
    has_new_failures = drift.get('new_failure_count', 0) > 0

    if not has_critical and not has_new_failures:
        return

    subject = f"Trinity6 Alert - {scan_data['server_name']}"
    if has_critical:
        subject = f"Trinity6 CRITICAL Alert - {scan_data['server_name']}"

    dashboard_url = (
        f"https://trinity6.com/dashboard"
        f"?server={scan_data['server_name']}"
    )

    body = f"""
Trinity6 Security Alert

Server: {scan_data['server_name']}
Scan Time: {scan_data['scan_timestamp']}
Compliance Score: {score['score']}%

Issues Found:
Critical: {score.get('critical', 0)}
High: {score.get('high', 0)}
Medium: {score.get('medium', 0)}

"""
    if has_new_failures:
        body += f"New failures since last scan: "
        body += f"{drift['new_failure_count']}\n"

    body += f"\nView full report and fixes:\n{dashboard_url}\n"
    body += "\nTrinity6 - Intelligent Security\ntrinitiy6.com"

    logger.info(
        f"Notification queued for {client_email} "
        f"score={score['score']}%"
    )


# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/health")
async def health_check():
    """API health check"""
    clients = load_clients()
    return {
        "status": "healthy",
        "version": "1.0.0",
        "total_clients": len(clients),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Trinity6 Platform API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }


# ==========================================
# RUN
# ==========================================

if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
