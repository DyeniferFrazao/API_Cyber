from flask import Flask, jsonify, request, render_template_string
import datetime

app = Flask(__name__)

dados = [
    {"id": 1, "projeto": "Projeto Alpha", "status": "Em andamento", "responsavel": "Admin"},
    {"id": 2, "projeto": "Projeto Beta", "status": "Concluído", "responsavel": "Equipe A"},
    {"id": 3, "projeto": "Projeto Gamma", "status": "Planejamento", "responsavel": "Equipe B"},
]

TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard Corporativo</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 40px; }
        h1 { color: #00d4ff; }
        .info { background: #16213e; padding: 15px; border-radius: 8px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #0f3460; color: #00d4ff; }
        .badge { background: #e94560; padding: 4px 10px; border-radius: 4px; font-size: 12px; }
        .badge.ok { background: #00b894; }
    </style>
</head>
<body>
    <h1>Dashboard Corporativo Interno</h1>
    <div class="info">
        <strong>Status:</strong> Online |
        <strong>Seu IP:</strong> {{ ip_cliente }} |
        <strong>Acesso em:</strong> {{ hora }}
    </div>
    <p>Este sistema é um <strong>ativo crítico</strong> acessível apenas via túnel VPN.</p>
    <table>
        <tr><th>ID</th><th>Projeto</th><th>Status</th><th>Responsável</th></tr>
        {% for p in projetos %}
        <tr>
            <td>{{ p.id }}</td>
            <td>{{ p.projeto }}</td>
            <td><span class="badge {{ 'ok' if p.status == 'Concluído' else '' }}">{{ p.status }}</span></td>
            <td>{{ p.responsavel }}</td>
        </tr>
        {% endfor %}
    </table>
    <br>
    <p><small>API JSON disponível em <a href="/api/projetos" style="color:#00d4ff;">/api/projetos</a></small></p>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(TEMPLATE,
        projetos=dados,
        ip_cliente=request.remote_addr,
        hora=datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S'))

@app.route('/api/projetos')
def api_projetos():
    return jsonify({"projetos": dados, "acesso_em": str(datetime.datetime.now())})

@app.route('/api/status')
def api_status():
    return jsonify({"status": "online", "ip_cliente": request.remote_addr})

if __name__ == '__main__':
    # Troque pelo seu IP VPN real
    app.run(host='100.96.0.5', port=5000, debug=False)