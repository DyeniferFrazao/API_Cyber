from flask import Flask, request, send_file, jsonify
import datetime
import os

app = Flask(__name__)

@app.route('/')
def index():
    return send_file('dashboard.html')

@app.route('/api/status')
def api_status():
    return jsonify({
        "status": "online",
        "servidor": "Admin-VPN-macOS",
        "ip_cliente": request.remote_addr,
        "acesso_em": str(datetime.datetime.now())
    })

if __name__ == '__main__':
    # Troque pelo seu IP VPN real
    app.run(host='100.96.1.2', port=5000, debug=False)