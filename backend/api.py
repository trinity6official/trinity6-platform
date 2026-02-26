#!/usr/bin/env python3
"""
Trinity6 Platform Backend API
Flask version - works on any Python version
No pydantic no Rust no compilation issues
"""

import os
import json
import uuid
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify


# ==========================================
# SETUP
# ==========================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('trinity6_api')

app = Flask(__name__)

DATA_DIR = Path("data")
CLIENTS_FILE = DATA_DIR / "clients.json"
SCANS_DIR = DATA_DIR / "scans"
TOKENS_FILE = DATA_DIR / "tokens.json"

DATA_DIR.mkdir(exist_ok=True)
SCANS_DIR.mkdir(exist_ok=True)


# ==========================================
# DATA HELPERS
# ==========================================

def load_json(filepath):
    if filepath.exists():
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}


def save_json(filepath, data):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def load_clients():
    return load_json(CLIENTS_FILE)


def save_clients(clients):
    save_json(CLIENTS_FILE, clients)


def load_tokens():
    return load_json(TOKENS_FILE)


def save_tokens(tokens):
    save_json(TOKENS_FILE, tokens)


def get_client_scans(client_id):
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


def save_scan(client_id, scan_data):
    scan_id = str(uuid.uuid4())[:8]
    scan_data['scan_id'] = scan_id
    client_scan_dir = SCANS_DIR / client_id
    client_scan_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_file = client_scan_dir / f"{timestamp}_{scan_id}.json"
    with open(scan_file, 'w') as f:
        json.dump(scan_data, f, indent=2)
    return scan_id


def calculate_score(checks):
    total = len(checks)
    if total == 0:
        return {
            'score': 0, 'total': 0,
            'pass': 0, 'fail': 0, 'warn': 0,
            'critical': 0, 'high': 0,
            'medium': 0, 'low': 0
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
        'score': score, 'total': total,
        'pass': passed, 'fail': failed, 'warn': warned,
        'critical': critical, 'high': high,
        'medium': medium, 'low': low
    }


def detect_drift(current_checks, previous_checks):
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


def get_server_status(score):
    if score >= 80:
        return 'good'
    elif score >= 60:
        return 'warning'
    return 'critical'


# ==========================================
# AUTH HELPERS
# ==========================================

def verify_agent_token(token):
    tokens = load_tokens()
    for client_id, token_data in tokens.items():
        if token_data.get('agent_token') == token:
            return client_id
    return None


def verify_session_token(token):
    tokens = load_tokens()
    for client_id, token_data in tokens.items():
        if token_data.get('session_token') == token:
            expires = token_data.get('session_expires')
            if expires:
                if datetime.fromisoformat(expires) \
                   > datetime.now():
                    return client_id
            else:
                return client_id
    return None


def verify_admin(req):
    secret = req.headers.get('X-Admin-Secret')
    expected = os.environ.get(
        'TRINITY6_ADMIN_SECRET', 'changeme'
    )
    return secret == expected


def agent_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '').strip()
        client_id = verify_agent_token(token)
        if not client_id:
            return jsonify({
                'error': 'Invalid agent token'
            }), 401
        return f(client_id, *args, **kwargs)
    return decorated


def session_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '').strip()
        client_id = verify_session_token(token)
        if not client_id:
            return jsonify({
                'error': 'Session expired. Please log in.'
            }), 401
        return f(client_id, *args, **kwargs)
    return decorated


# ==========================================
# HEALTH CHECK
# ==========================================

@app.route('/health')
def health_check():
    clients = load_clients()
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'total_clients': len(clients),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/')
def root():
    return jsonify({
        'name': 'Trinity6 Platform API',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'health': '/health',
            'scan': '/api/v1/scan/results',
            'login': '/api/v1/auth/login',
            'dashboard': '/api/v1/dashboard/overview',
            'admin': '/api/v1/admin/clients'
        }
    })


# ==========================================
# AGENT ENDPOINTS
# ==========================================

@app.route('/api/v1/scan/results', methods=['POST'])
@agent_required
def receive_scan_results(client_id):
    """Receive scan results from Trinity6 agent"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    if data.get('client_id') != client_id:
        return jsonify({'error': 'Client ID mismatch'}), 403

    clients = load_clients()
    if client_id not in clients:
        return jsonify({'error': 'Client not found'}), 404

    score = calculate_score(data.get('checks', []))
    data['score'] = score

    previous_scans = get_client_scans(client_id)
    drift = {}
    if previous_scans:
        for prev in previous_scans:
            if prev.get('server_name') == data.get('server_name'):
                drift = detect_drift(
                    data.get('checks', []),
                    prev.get('checks', [])
                )
                data['drift'] = drift
                data['previous_score'] = prev.get(
                    'score', {}
                ).get('score')
                break

    scan_id = save_scan(client_id, data)

    if not clients[client_id].get('servers'):
        clients[client_id]['servers'] = {}

    clients[client_id]['servers'][data['server_name']] = {
        'last_scan': data.get('scan_timestamp'),
        'last_score': score['score'],
        'last_scan_id': scan_id,
        'os_info': data.get('os_info'),
        'hostname': data.get('hostname')
    }
    clients[client_id]['last_activity'] = \
        datetime.now().isoformat()
    save_clients(clients)

    logger.info(
        f"Scan from {client_id} "
        f"server={data.get('server_name')} "
        f"score={score['score']}%"
    )

    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'score': score['score'],
        'message': f"Scan processed. Score: {score['score']}%"
    })


# ==========================================
# AUTH ENDPOINTS
# ==========================================

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """Client dashboard login"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    email = data.get('email', '').lower()
    password = data.get('password', '')

    clients = load_clients()
    tokens = load_tokens()

    client_id = None
    for cid, client in clients.items():
        if client.get('email', '').lower() == email:
            stored_hash = client.get('password_hash', '')
            input_hash = hashlib.sha256(
                password.encode()
            ).hexdigest()
            if stored_hash == input_hash:
                client_id = cid
                break

    if not client_id:
        return jsonify({
            'error': 'Invalid email or password'
        }), 401

    session_token = secrets.token_urlsafe(32)
    expires = (
        datetime.now() + timedelta(days=7)
    ).isoformat()

    if client_id not in tokens:
        tokens[client_id] = {}
    tokens[client_id]['session_token'] = session_token
    tokens[client_id]['session_expires'] = expires
    save_tokens(tokens)

    return jsonify({
        'success': True,
        'session_token': session_token,
        'client_id': client_id,
        'client_name': clients[client_id].get('name'),
        'company': clients[client_id].get('company')
    })


# ==========================================
# DASHBOARD ENDPOINTS
# ==========================================

@app.route('/api/v1/dashboard/overview')
@session_required
def dashboard_overview(client_id):
    """Dashboard overview for client"""
    clients = load_clients()
    if client_id not in clients:
        return jsonify({'error': 'Client not found'}), 404

    client = clients[client_id]
    servers = client.get('servers', {})

    server_list = []
    total_score = 0
    for server_name, server_data in servers.items():
        score = server_data.get('last_score', 0)
        server_list.append({
            'name': server_name,
            'hostname': server_data.get('hostname'),
            'os_info': server_data.get('os_info'),
            'last_scan': server_data.get('last_scan'),
            'score': score,
            'status': get_server_status(score)
        })
        total_score += score

    avg_score = round(
        total_score / len(servers)
    ) if servers else 0

    return jsonify({
        'client_name': client.get('name'),
        'company': client.get('company'),
        'plan': client.get('plan', 'starter'),
        'total_servers': len(servers),
        'average_score': avg_score,
        'overall_status': get_server_status(avg_score),
        'servers': sorted(
            server_list, key=lambda x: x['score']
        ),
        'last_activity': client.get('last_activity')
    })


@app.route('/api/v1/dashboard/server/<server_name>')
@session_required
def server_detail(client_id, server_name):
    """Detailed scan results for a server"""
    scans = get_client_scans(client_id)
    server_scans = [
        s for s in scans
        if s.get('server_name') == server_name
    ]

    if not server_scans:
        return jsonify({
            'error': 'No scans found for this server'
        }), 404

    latest = server_scans[0]
    score_history = []
    for scan in server_scans[:10]:
        score_history.append({
            'date': scan.get(
                'scan_timestamp', ''
            )[:10],
            'score': scan.get(
                'score', {}
            ).get('score', 0)
        })

    checks = latest.get('checks', [])
    failed_checks = [
        c for c in checks if c.get('status') == 'FAIL'
    ]
    severity_order = {
        'critical': 0, 'high': 1,
        'medium': 2, 'low': 3
    }
    failed_checks.sort(
        key=lambda x: severity_order.get(
            x.get('severity', 'low'), 3
        )
    )

    return jsonify({
        'server_name': server_name,
        'hostname': latest.get('hostname'),
        'os_info': latest.get('os_info'),
        'last_scan': latest.get('scan_timestamp'),
        'score': latest.get('score', {}),
        'previous_score': latest.get('previous_score'),
        'drift': latest.get('drift', {}),
        'failed_checks': failed_checks,
        'all_checks': checks,
        'score_history': score_history,
        'scan_id': latest.get('scan_id')
    })


@app.route('/api/v1/dashboard/alerts')
@session_required
def get_alerts(client_id):
    """Active alerts for client"""
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
                'message': f"Score critically low: {score}%",
                'timestamp': scan.get('scan_timestamp')
            })

        drift = scan.get('drift', {})
        for failure in drift.get('new_failures', []):
            if failure.get('severity') in ['critical', 'high']:
                alerts.append({
                    'type': 'new_failure',
                    'severity': failure['severity'],
                    'server': server,
                    'message': f"New: {failure['description']}",
                    'timestamp': scan.get('scan_timestamp')
                })

    return jsonify({
        'total_alerts': len(alerts),
        'alerts': alerts
    })


@app.route('/api/v1/dashboard/history')
@session_required
def scan_history(client_id):
    """Scan history for all servers"""
    scans = get_client_scans(client_id)
    history = []
    for scan in scans[:50]:
        history.append({
            'scan_id': scan.get('scan_id'),
            'server_name': scan.get('server_name'),
            'timestamp': scan.get('scan_timestamp'),
            'score': scan.get('score', {}).get('score', 0),
            'failures': scan.get('score', {}).get('fail', 0),
            'drift': scan.get(
                'drift', {}
            ).get('has_changes', False)
        })
    return jsonify({
        'total_scans': len(history),
        'history': history
    })


# ==========================================
# ADMIN ENDPOINTS
# ==========================================

@app.route('/api/v1/admin/register_client',
           methods=['POST'])
def register_client():
    """Register new client"""
    if not verify_admin(request):
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    client_id = str(uuid.uuid4())[:8]
    agent_token = secrets.token_urlsafe(32)
    temp_password = secrets.token_urlsafe(12)
    password_hash = hashlib.sha256(
        temp_password.encode()
    ).hexdigest()

    clients = load_clients()
    clients[client_id] = {
        'name': data.get('name'),
        'company': data.get('company'),
        'email': data.get('email'),
        'plan': data.get('plan', 'starter'),
        'password_hash': password_hash,
        'created_at': datetime.now().isoformat(),
        'servers': {},
        'scan_frequency_days': 7,
        'notifications_enabled': True
    }
    save_clients(clients)

    tokens = load_tokens()
    tokens[client_id] = {'agent_token': agent_token}
    save_tokens(tokens)

    logger.info(
        f"New client: {data.get('company')} id={client_id}"
    )

    return jsonify({
        'success': True,
        'client_id': client_id,
        'agent_token': agent_token,
        'temp_password': temp_password,
        'dashboard_url': 'https://trinity6-platform.onrender.com',
        'install_command': (
            f"curl -s https://trinity6-platform.onrender.com"
            f"/install.sh | sudo bash -s -- "
            f"--client-id {client_id} "
            f"--token {agent_token} "
            f"--email {data.get('email')}"
        )
    })


@app.route('/api/v1/admin/clients')
def list_clients():
    """List all clients"""
    if not verify_admin(request):
        return jsonify({'error': 'Unauthorized'}), 403

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

    return jsonify({
        'total_clients': len(summary),
        'clients': sorted(
            summary,
            key=lambda x: x.get('last_activity', ''),
            reverse=True
        )
    })
@app.route('/dashboard')
def serve_dashboard():
    """Serve dashboard HTML"""
    dashboard_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'dashboard', 'index.html'
    )
    if os.path.exists(dashboard_path):
        with open(dashboard_path, 'r') as f:
            return f.read(), 200, {
                'Content-Type': 'text/html'
            }
    return "Dashboard not found", 404


# ==========================================
# RUN
# ==========================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
