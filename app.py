# app.py
from flask import Flask, jsonify, request
import datetime

app = Flask(__name__)


dados_sensiveis = [
    {"id": 1, "projeto": "Projeto Alpha", "status": "Em andamento", "responsavel": "Admin"},
    {"id": 2, "projeto": "Projeto Beta", "status": "Concluído", "responsavel": "Equipe A"},
    {"id": 3, "projeto": "Projeto Gamma", "status": "Planejamento", "responsavel": "Equipe B"},
]

@app.route('/')
def index():
    return '''<h1>Dashboard Corporativo Interno</h1>
              <p>Ativo crítico protegido por VPN</p>
              <p>Acesse /api/projetos para ver os dados.</p>'''

@app.route('/api/projetos', methods=['GET'])
def listar_projetos():
    return jsonify({"projetos": dados_sensiveis, "acesso_em": str(datetime.datetime.now())})

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({"status": "online", "servidor": "Admin-VPN", "ip_cliente": request.remote_addr})

if __name__ == '__main__':
    # CRÍTICO: bind APENAS no IP da VPN, não no 0.0.0.0
    app.run(host='IP_VPN_AQUI', port=5000)