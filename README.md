<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/VPN-CloudConnexa-EA7E20?style=for-the-badge&logo=openvpn&logoColor=white"/>
</p>

<h1 align="center">🛡️ CyberShield SOC</h1>

<p align="center">
  Dashboard de operações de segurança com arquitetura Zero Trust.<br>
  Acessível exclusivamente via túnel VPN autenticado.
</p>

---

## 📚 Contexto Acadêmico

Projeto desenvolvido como Trabalho Discente Final da disciplina de **Cibersegurança Aplicada** do curso de Ciência da Computação — **Universidade de Passo Fundo (UPF)**, 2026.

---

## 🔍 Sobre

O CyberShield SOC é uma aplicação web que simula um ativo crítico corporativo, projetada com múltiplas camadas de defesa em profundidade. A superfície de ataque é nula fora do ambiente VPN.

### Camadas de segurança implementadas

- Restrição de acesso por sub-rede VPN
- Autenticação obrigatória com sessão segura
- Controle de acesso baseado em papéis (RBAC)
- Proteção contra força bruta e abuso de requisições
- Hardening via headers HTTP
- Registro completo de auditoria

---

## 📋 Pré-requisitos

- Python 3.10+
- OpenVPN Connect configurado e conectado ao CloudConnexa
- Conta ativa no CloudConnexa com MFA habilitado

---

## ⚙️ Instalação

```bash
git clone https://github.com/seu-usuario/cybershield-soc.git
cd cybershield-soc
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🔧 Configuração

Antes de rodar, é necessário configurar as variáveis no `app.py`:

1. Conecte-se à VPN
2. Identifique o IP atribuído ao túnel:
   ```bash
   # macOS
   ifconfig | grep -A 5 "utun"

   # Linux
   ip addr show tun0

   # Windows
   ipconfig
   ```
3. Edite `VPN_HOST` no `app.py` com o IP encontrado
4. Altere as credenciais padrão dos usuários antes de usar

> ⚠️ **Importante:** nunca utilize as credenciais de exemplo em ambiente de produção. Troque todas as senhas antes da primeira execução.

---

## 🚀 Uso

```bash
python3 app.py
```

Acesse via navegador no endereço exibido no terminal. O acesso só é possível a partir de dispositivos conectados à VPN.

---

## 📁 Estrutura

```
cybershield-soc/
├── .gitignore
├── .gitattributes
├── requirements.txt
├── README.md
├── app.py                  # Servidor com camadas de segurança
└── dashboard.html          # Interface do dashboard
```

---

## 🧪 Validação

O projeto contempla os seguintes cenários de teste:

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| 1 | Acesso sem VPN | Conexão recusada |
| 2 | Acesso com VPN + credenciais válidas | Dashboard disponível |
| 3 | Acesso com papel sem permissão | Recurso negado (403) |
| 4 | Requisições excessivas | Bloqueio temporário (429) |
| 5 | Tentativas de login incorretas | IP bloqueado temporariamente |
| 6 | Inspeção de headers HTTP | Headers de segurança presentes |

---

## 🔗 Tecnologias

- **Python / Flask** — back-end
- **OpenVPN CloudConnexa** — infraestrutura VPN + MFA
- **Cyber Shield** — filtragem DNS
- **HTML / CSS / JS** — interface do dashboard

---

## 📄 Licença

Projeto acadêmico — Cibersegurança Aplicada, UPF 2026.
