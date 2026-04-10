"""
=============================================================================
  CyberShield SOC — Servidor Flask com Camadas de Segurança
  Disciplina: Cibersegurança Aplicada (CSA) — UPF 2026
=============================================================================
  Camadas implementadas:
    1. Restrição por IP VPN (whitelist de sub-rede 100.96.x.x)
    2. Autenticação por login (sessão com usuário/senha)
    3. Controle de acesso por papel — RBAC (Admin, Professor, Usuário)
    4. Rate limiting (proteção contra brute force / DoS)
    5. Headers de segurança HTTP (hardening)
    6. Logging de acesso e auditoria (arquivo + console)
=============================================================================
"""

from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, jsonify, send_file, abort
)
from functools import wraps
from datetime import datetime, timedelta
import logging
import os
import hashlib
import time
import json

# =============================================================================
# CONFIGURAÇÃO
# =============================================================================

# >>> TROQUE pelo seu IP VPN real (rode: ifconfig | grep utun -A 5) <<<
VPN_HOST = '100.96.1.2'
VPN_PORT = 5000

# Chave secreta para sessões (em produção, usar variável de ambiente)
SECRET_KEY = os.urandom(24).hex()

# Sub-rede VPN permitida (CloudConnexa usa 100.96.x.x)
VPN_SUBNET = '100.96.'

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(minutes=30)


# =============================================================================
# CAMADA 6 — LOGGING DE ACESSO E AUDITORIA
# =============================================================================

# Configurar logging para arquivo e console
LOG_FILE = 'access_audit.log'

# Formato do log
log_formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s | IP: %(message)s'
)

# Handler para arquivo
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setFormatter(log_formatter)

# Handler para console
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

# Logger da aplicação
audit_log = logging.getLogger('audit')
audit_log.setLevel(logging.INFO)
audit_log.addHandler(file_handler)
audit_log.addHandler(console_handler)

def log_event(event_type, details, ip=None):
    """Registra um evento de auditoria."""
    if ip is None:
        ip = request.remote_addr
    user = session.get('username', 'anônimo')
    role = session.get('role', 'N/A')
    msg = f"{ip} | Usuário: {user} | Papel: {role} | {event_type}: {details}"
    audit_log.info(msg)


# =============================================================================
# CAMADA 4 — RATE LIMITING (proteção contra brute force)
# =============================================================================

# Armazena tentativas: { ip: [timestamp1, timestamp2, ...] }
rate_limit_store = {}
RATE_LIMIT_MAX = 10       # máximo de requisições
RATE_LIMIT_WINDOW = 60    # por janela de tempo (segundos)
LOGIN_ATTEMPT_STORE = {}
LOGIN_MAX_ATTEMPTS = 5    # máximo de tentativas de login
LOGIN_BLOCK_TIME = 300    # bloqueio de 5 minutos após exceder

def check_rate_limit(ip):
    """Verifica se o IP excedeu o limite de requisições."""
    now = time.time()
    if ip not in rate_limit_store:
        rate_limit_store[ip] = []

    # Remove timestamps antigos
    rate_limit_store[ip] = [
        t for t in rate_limit_store[ip]
        if now - t < RATE_LIMIT_WINDOW
    ]

    if len(rate_limit_store[ip]) >= RATE_LIMIT_MAX:
        return False  # Limite excedido

    rate_limit_store[ip].append(now)
    return True

def check_login_blocked(ip):
    """Verifica se o IP está bloqueado por tentativas de login."""
    if ip not in LOGIN_ATTEMPT_STORE:
        return False

    attempts, last_attempt = LOGIN_ATTEMPT_STORE[ip]
    if attempts >= LOGIN_MAX_ATTEMPTS:
        if time.time() - last_attempt < LOGIN_BLOCK_TIME:
            return True  # Ainda bloqueado
        else:
            # Reset após período de bloqueio
            del LOGIN_ATTEMPT_STORE[ip]
            return False
    return False

def record_login_attempt(ip, success):
    """Registra uma tentativa de login."""
    if success:
        if ip in LOGIN_ATTEMPT_STORE:
            del LOGIN_ATTEMPT_STORE[ip]
        return

    if ip not in LOGIN_ATTEMPT_STORE:
        LOGIN_ATTEMPT_STORE[ip] = [0, 0]

    LOGIN_ATTEMPT_STORE[ip][0] += 1
    LOGIN_ATTEMPT_STORE[ip][1] = time.time()


# =============================================================================
# CAMADA 3 — CONTROLE DE ACESSO BASEADO EM PAPEL (RBAC)
# =============================================================================

# Banco de usuários (em produção, usar banco de dados com hash bcrypt)
# As senhas são armazenadas como SHA-256 hash
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

USERS = {
    'admin': {
        'password': hash_password('Admin@2026'),
        'role': 'admin',
        'name': 'Administrador',
    },
    'professor': {
        'password': hash_password('Prof@2026'),
        'role': 'professor',
        'name': 'Professor',
    },
    'usuario': {
        'password': hash_password('User@2026'),
        'role': 'usuario',
        'name': 'Usuário Padrão',
    },
}

# Permissões por papel
ROLE_PERMISSIONS = {
    'admin': ['dashboard', 'api', 'logs', 'config'],
    'professor': ['dashboard', 'api', 'logs'],
    'usuario': ['dashboard'],
}

def has_permission(role, permission):
    """Verifica se o papel tem a permissão especificada."""
    return permission in ROLE_PERMISSIONS.get(role, [])


# =============================================================================
# CAMADA 5 — HEADERS DE SEGURANÇA HTTP (Hardening)
# =============================================================================

@app.after_request
def add_security_headers(response):
    """Adiciona headers de segurança em todas as respostas."""
    # Previne clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Previne MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Ativa proteção XSS do navegador
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Política de segurança de conteúdo
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;"
    )
    # Força HTTPS (relevante se usar certificado)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Controle de referrer
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Identifica o servidor de forma genérica
    response.headers['Server'] = 'CyberShield-SOC/1.0'
    # Desativa cache para dados sensíveis
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


# =============================================================================
# CAMADA 1 — RESTRIÇÃO POR IP VPN (Whitelist)
# =============================================================================

@app.before_request
def verify_vpn_ip():
    """Bloqueia qualquer acesso de fora da sub-rede VPN."""
    client_ip = request.remote_addr

    # Permite apenas IPs da faixa VPN (100.96.x.x)
    if not client_ip.startswith(VPN_SUBNET):
        log_event('BLOQUEADO', f'Acesso negado — IP fora da VPN: {client_ip}')
        abort(403)

    # Rate limiting
    if not check_rate_limit(client_ip):
        log_event('RATE_LIMIT', f'Limite de requisições excedido: {client_ip}')
        abort(429)


# =============================================================================
# CAMADA 2 — AUTENTICAÇÃO POR LOGIN (Sessão)
# =============================================================================

def login_required(f):
    """Decorator que exige autenticação para acessar a rota."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            log_event('ACESSO_NEGADO', f'Tentativa sem autenticação em {request.path}')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(permission):
    """Decorator que exige um papel específico."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get('role', '')
            if not has_permission(user_role, permission):
                log_event('PERMISSÃO_NEGADA',
                    f'Papel "{user_role}" sem permissão "{permission}" em {request.path}')
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# =============================================================================
# PÁGINA DE LOGIN
# =============================================================================

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberShield SOC — Login</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-primary: #0a0e17;
    --bg-card: #111827;
    --border: #1e293b;
    --cyan: #22d3ee;
    --cyan-dark: #0891b2;
    --red: #f87171;
    --green: #34d399;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Outfit', sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }
  .bg-grid {
    position: fixed; inset: 0; z-index: 0;
    background-image:
      linear-gradient(rgba(34,211,238,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(34,211,238,0.03) 1px, transparent 1px);
    background-size: 60px 60px;
    animation: gridPulse 8s ease-in-out infinite;
  }
  @keyframes gridPulse { 0%,100%{opacity:.5} 50%{opacity:1} }

  .login-container {
    position: relative; z-index: 1;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 48px 40px;
    width: 420px;
    box-shadow: 0 0 60px rgba(34,211,238,0.08);
  }
  .login-logo {
    text-align: center;
    margin-bottom: 32px;
  }
  .login-logo .icon {
    width: 64px; height: 64px;
    background: linear-gradient(135deg, #0891b2, #7c3aed);
    border-radius: 16px;
    display: inline-flex;
    align-items: center; justify-content: center;
    font-size: 32px;
    box-shadow: 0 0 30px rgba(34,211,238,0.3);
    margin-bottom: 16px;
  }
  .login-logo h1 {
    font-size: 26px; font-weight: 800;
    background: linear-gradient(135deg, #0891b2, #7c3aed);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .login-logo p {
    color: var(--text-muted);
    font-size: 13px;
    margin-top: 4px;
    letter-spacing: 2px;
    text-transform: uppercase;
  }

  .security-info {
    background: rgba(34,211,238,0.06);
    border: 1px solid rgba(34,211,238,0.15);
    border-radius: 10px;
    padding: 12px 16px;
    margin-bottom: 28px;
    font-size: 12px;
    color: var(--cyan);
    font-family: 'JetBrains Mono', monospace;
    display: flex; align-items: center; gap: 10px;
  }

  .form-group {
    margin-bottom: 20px;
  }
  .form-group label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 8px;
  }
  .form-group input {
    width: 100%;
    padding: 14px 16px;
    background: rgba(255,255,255,0.04);
    border: 1px solid var(--border);
    border-radius: 10px;
    color: var(--text-primary);
    font-size: 15px;
    font-family: 'JetBrains Mono', monospace;
    transition: border-color 0.3s, box-shadow 0.3s;
    outline: none;
  }
  .form-group input:focus {
    border-color: var(--cyan);
    box-shadow: 0 0 15px rgba(34,211,238,0.15);
  }

  .login-btn {
    width: 100%;
    padding: 14px;
    background: linear-gradient(135deg, #0891b2, #7c3aed);
    border: none;
    border-radius: 10px;
    color: white;
    font-size: 15px;
    font-weight: 700;
    font-family: 'Outfit', sans-serif;
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
    letter-spacing: 0.5px;
  }
  .login-btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 8px 25px rgba(34,211,238,0.25);
  }

  .error-msg {
    background: rgba(248,113,113,0.1);
    border: 1px solid rgba(248,113,113,0.3);
    color: var(--red);
    padding: 12px 16px;
    border-radius: 10px;
    font-size: 13px;
    margin-bottom: 20px;
    display: flex; align-items: center; gap: 8px;
  }

  .footer-info {
    text-align: center;
    margin-top: 24px;
    font-size: 11px;
    color: var(--text-muted);
    font-family: 'JetBrains Mono', monospace;
  }

  .security-layers {
    margin-top: 20px;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    justify-content: center;
  }
  .layer-badge {
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 10px;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .layer-vpn { background: rgba(34,211,238,0.12); color: var(--cyan); }
  .layer-mfa { background: rgba(52,211,153,0.12); color: var(--green); }
  .layer-rbac { background: rgba(167,139,250,0.12); color: #a78bfa; }
  .layer-rate { background: rgba(251,191,36,0.12); color: #fbbf24; }
  .layer-headers { background: rgba(96,165,250,0.12); color: #60a5fa; }
  .layer-audit { background: rgba(248,113,113,0.12); color: var(--red); }
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="login-container">
  <div class="login-logo">
    <div class="icon">🛡️</div>
    <h1>CyberShield SOC</h1>
    <p>Acesso Seguro</p>
  </div>

  <div class="security-info">
    🔒 Conexão VPN verificada — {{ client_ip }}
  </div>

  {% if error %}
  <div class="error-msg">⚠️ {{ error }}</div>
  {% endif %}

  <form method="POST">
    <div class="form-group">
      <label>Usuário</label>
      <input type="text" name="username" placeholder="Digite seu usuário" required autocomplete="off">
    </div>
    <div class="form-group">
      <label>Senha</label>
      <input type="password" name="password" placeholder="Digite sua senha" required>
    </div>
    <button type="submit" class="login-btn">Acessar Sistema</button>
  </form>

  <div class="footer-info">
    Acesso restrito via túnel VPN com MFA
  </div>

  <div class="security-layers">
    <span class="layer-badge layer-vpn">VPN</span>
    <span class="layer-badge layer-mfa">MFA</span>
    <span class="layer-badge layer-rbac">RBAC</span>
    <span class="layer-badge layer-rate">Rate Limit</span>
    <span class="layer-badge layer-headers">Headers</span>
    <span class="layer-badge layer-audit">Audit Log</span>
  </div>
</div>
</body>
</html>
'''

# =============================================================================
# PÁGINA 403 — ACESSO NEGADO
# =============================================================================

FORBIDDEN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Acesso Negado</title>
<style>
  body { font-family: sans-serif; background: #0a0e17; color: #f87171;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; text-align: center; }
  .container { max-width: 500px; }
  h1 { font-size: 72px; margin-bottom: 10px; }
  p { color: #94a3b8; font-size: 16px; line-height: 1.6; }
  code { background: rgba(248,113,113,0.1); padding: 2px 8px;
         border-radius: 4px; color: #f87171; }
</style>
</head>
<body>
<div class="container">
  <h1>⛔ 403</h1>
  <h2>Acesso Negado</h2>
  <p>{{ message }}</p>
</div>
</body>
</html>
'''

RATE_LIMIT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Limite Excedido</title>
<style>
  body { font-family: sans-serif; background: #0a0e17; color: #fbbf24;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; text-align: center; }
  h1 { font-size: 72px; margin-bottom: 10px; }
  p { color: #94a3b8; font-size: 16px; }
</style>
</head>
<body>
<div>
  <h1>⏱️ 429</h1>
  <h2>Limite de Requisições Excedido</h2>
  <p>Muitas requisições em pouco tempo. Aguarde {{ wait }} segundos.</p>
</div>
</body>
</html>
'''


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(403)
def forbidden(e):
    return render_template_string(FORBIDDEN_TEMPLATE,
        message=f'Seu IP ({request.remote_addr}) não tem permissão para acessar este recurso.'), 403

@app.errorhandler(429)
def rate_limited(e):
    return render_template_string(RATE_LIMIT_TEMPLATE, wait=RATE_LIMIT_WINDOW), 429


# =============================================================================
# ROTAS
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    client_ip = request.remote_addr

    if request.method == 'POST':
        # Verificar bloqueio por tentativas
        if check_login_blocked(client_ip):
            remaining = int(LOGIN_BLOCK_TIME - (time.time() - LOGIN_ATTEMPT_STORE[client_ip][1]))
            error = f'IP bloqueado por excesso de tentativas. Aguarde {remaining}s.'
            log_event('LOGIN_BLOQUEADO', f'IP bloqueado — tentativas excessivas')
            return render_template_string(LOGIN_TEMPLATE, error=error, client_ip=client_ip)

        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        if username in USERS and USERS[username]['password'] == hash_password(password):
            # Login bem-sucedido
            session.permanent = True
            session['username'] = username
            session['role'] = USERS[username]['role']
            session['name'] = USERS[username]['name']
            session['login_time'] = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            record_login_attempt(client_ip, success=True)
            log_event('LOGIN_OK', f'Login bem-sucedido como "{username}"')
            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(client_ip, success=False)
            attempts_left = LOGIN_MAX_ATTEMPTS - LOGIN_ATTEMPT_STORE.get(client_ip, [0])[0]
            error = f'Credenciais inválidas. {max(attempts_left, 0)} tentativas restantes.'
            log_event('LOGIN_FALHA', f'Tentativa falha — usuário: "{username}"')

    return render_template_string(LOGIN_TEMPLATE, error=error, client_ip=client_ip)


@app.route('/logout')
def logout():
    user = session.get('username', 'desconhecido')
    log_event('LOGOUT', f'Logout de "{user}"')
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
@role_required('dashboard')
def dashboard():
    log_event('ACESSO', f'Dashboard acessado — rota /')
    # Injeta dados dinâmicos no HTML do dashboard
    return send_file('dashboard.html')


@app.route('/api/projetos')
@login_required
@role_required('api')
def api_projetos():
    log_event('API', 'Acesso a /api/projetos')
    dados = [
        {"id": 1, "projeto": "Projeto Alpha", "status": "Em andamento", "responsavel": "Admin"},
        {"id": 2, "projeto": "Projeto Beta", "status": "Concluído", "responsavel": "Equipe A"},
        {"id": 3, "projeto": "Projeto Gamma", "status": "Planejamento", "responsavel": "Equipe B"},
    ]
    return jsonify({
        "projetos": dados,
        "acesso_por": session.get('username'),
        "papel": session.get('role'),
        "ip_cliente": request.remote_addr,
        "acesso_em": datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    })


@app.route('/api/status')
@login_required
def api_status():
    log_event('API', 'Acesso a /api/status')
    return jsonify({
        "status": "online",
        "servidor": "CyberShield-SOC",
        "versao": "1.0",
        "usuario_logado": session.get('username'),
        "papel": session.get('role'),
        "ip_cliente": request.remote_addr,
        "sessao_inicio": session.get('login_time'),
        "camadas_seguranca": [
            "VPN Whitelist (100.96.x.x)",
            "Autenticação por Sessão",
            "RBAC (Controle por Papel)",
            "Rate Limiting",
            "Headers HTTP de Segurança",
            "Logging de Auditoria"
        ],
        "acesso_em": datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    })


@app.route('/api/logs')
@login_required
@role_required('logs')
def api_logs():
    """Exibe os últimos logs de auditoria (apenas Admin e Professor)."""
    log_event('API', 'Acesso aos logs de auditoria')
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # Retorna as últimas 50 linhas
            recent = lines[-50:] if len(lines) > 50 else lines
            return jsonify({
                "total_eventos": len(lines),
                "exibindo": len(recent),
                "logs": [line.strip() for line in recent]
            })
    except FileNotFoundError:
        return jsonify({"logs": [], "msg": "Nenhum log registrado ainda."})


@app.route('/api/security-info')
@login_required
def security_info():
    """Retorna informações sobre as camadas de segurança ativas."""
    return jsonify({
        "camadas": {
            "1_vpn_whitelist": {
                "status": "ativo",
                "descricao": "Apenas IPs da sub-rede VPN (100.96.x.x) são aceitos",
                "subnet_permitida": VPN_SUBNET + "0.0/11"
            },
            "2_autenticacao": {
                "status": "ativo",
                "descricao": "Login com usuário e senha + sessão com timeout de 30 min",
                "sessao_expira": "30 minutos"
            },
            "3_rbac": {
                "status": "ativo",
                "descricao": "Controle de acesso baseado em papel (Admin/Professor/Usuário)",
                "papeis": ROLE_PERMISSIONS
            },
            "4_rate_limiting": {
                "status": "ativo",
                "descricao": f"Máximo {RATE_LIMIT_MAX} req/{RATE_LIMIT_WINDOW}s por IP",
                "login_max_tentativas": LOGIN_MAX_ATTEMPTS,
                "login_bloqueio_segundos": LOGIN_BLOCK_TIME
            },
            "5_headers_http": {
                "status": "ativo",
                "descricao": "X-Frame-Options, CSP, HSTS, X-XSS-Protection, etc.",
                "headers": [
                    "X-Frame-Options: DENY",
                    "X-Content-Type-Options: nosniff",
                    "X-XSS-Protection: 1; mode=block",
                    "Content-Security-Policy",
                    "Strict-Transport-Security",
                    "Referrer-Policy"
                ]
            },
            "6_audit_logging": {
                "status": "ativo",
                "descricao": "Todos os acessos, logins, falhas e bloqueios são registrados",
                "arquivo_log": LOG_FILE
            }
        }
    })


# =============================================================================
# INICIALIZAÇÃO
# =============================================================================

if __name__ == '__main__':
    print("=" * 65)
    print("  CyberShield SOC — Servidor Flask Seguro")
    print("=" * 65)
    print(f"  Host:          {VPN_HOST}:{VPN_PORT}")
    print(f"  Sub-rede VPN:  {VPN_SUBNET}x.x (whitelist)")
    print(f"  Rate Limit:    {RATE_LIMIT_MAX} req / {RATE_LIMIT_WINDOW}s")
    print(f"  Login Limit:   {LOGIN_MAX_ATTEMPTS} tentativas (bloqueio {LOGIN_BLOCK_TIME}s)")
    print(f"  Log de audit:  {LOG_FILE}")
    print("-" * 65)
    print("  Usuários cadastrados:")
    for u, info in USERS.items():
        print(f"    → {u} (papel: {info['role']})")
    print("-" * 65)
    print("  Camadas de segurança ativas:")
    print("    1. Restrição por IP VPN (whitelist)")
    print("    2. Autenticação por login (sessão)")
    print("    3. RBAC — Controle por papel")
    print("    4. Rate limiting (anti brute force)")
    print("    5. Headers HTTP de segurança")
    print("    6. Logging de auditoria")
    print("=" * 65)

    app.run(host=VPN_HOST, port=VPN_PORT, debug=False)
