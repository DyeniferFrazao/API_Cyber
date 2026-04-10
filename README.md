<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-3.1.1-000000?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/OpenVPN-CloudConnexa-EA7E20?style=for-the-badge&logo=openvpn&logoColor=white"/>
  <img src="https://img.shields.io/badge/Licença-MIT-22d3ee?style=for-the-badge"/>
</p>

<h1 align="center">🛡️ CyberShield SOC</h1>

<p align="center">
  <strong>Dashboard de Segurança com Arquitetura Zero Trust</strong><br>
  Aplicação Flask protegida por 6 camadas de segurança, acessível exclusivamente via túnel VPN.
</p>

<p align="center">
  <a href="#-sobre-a-disciplina">Disciplina</a> •
  <a href="#-visão-geral">Visão Geral</a> •
  <a href="#-camadas-de-segurança">Segurança</a> •
  <a href="#-pré-requisitos">Pré-requisitos</a> •
  <a href="#-instalação">Instalação</a> •
  <a href="#-uso">Uso</a> •
  <a href="#-estrutura-do-projeto">Estrutura</a> •
  <a href="#-testes">Testes</a>
</p>

---

## 📚 Sobre a Disciplina

| | |
|---|---|
| **Instituição** | Universidade de Passo Fundo (UPF) |
| **Curso** | Ciência da Computação — 8º Nível |
| **Instituto** | Instituto de Tecnologia (ITEC) |
| **Disciplina** | Cibersegurança Aplicada (CSA) |
| **Trabalho** | Trabalho Discente Final 2026 |
| **Projeto** | Arquitetura Segura de Acesso Remoto com OpenVPN |

### Objetivo

Projetar, configurar e validar uma infraestrutura de acesso remoto seguro utilizando o OpenVPN CloudConnexa, com foco na implementação de uma aplicação funcional cuja superfície de ataque seja nula fora do túnel VPN, aplicando controles fundamentais de cibersegurança.

### Competências Demonstradas

- Autenticação forte (MFA) para todos os usuários
- Controle de acesso baseado em identidade e papel (RBAC)
- Filtragem e bloqueio de sites via Cyber Shield
- Isolamento completo de ativo crítico via túnel VPN
- Logging, auditoria e comprovação prática por evidências

---

## 🔍 Visão Geral

O **CyberShield SOC** é um dashboard de operações de segurança (Security Operations Center) desenvolvido em Flask, que simula um ativo crítico corporativo. A aplicação foi projetada para ser completamente invisível fora da rede VPN — implementando o conceito de **Zero Trust**: nenhum acesso é confiável por padrão, toda conexão deve ser verificada.

### Arquitetura

```
┌──────────────────────────────────────────────────────────┐
│                      INTERNET                            │
│                   (acesso bloqueado)                     │
└──────────────────────┬───────────────────────────────────┘
                       ✕ Superfície de ataque = 0
                       │
┌──────────────────────┴───────────────────────────────────┐
│              OpenVPN CloudConnexa                         │
│         ┌──────────────────────────┐                     │
│         │      Cyber Shield        │                     │
│         │  (filtragem DNS/sites)   │                     │
│         └──────────────────────────┘                     │
│                                                          │
│   👤 Admin ──────┐                                       │
│   (100.96.1.2)   │                                       │
│                  │    Túnel VPN (WireGuard/OpenVPN)       │
│   👤 Professor ──┼──────────────────────┐                │
│   (100.96.1.X)   │                      │                │
│                  │                      ▼                │
│   👤 Usuário ────┘        ┌─────────────────────┐        │
│   (100.96.1.X)            │   CyberShield SOC   │        │
│                           │   Flask :5000        │        │
│                           │   (máquina Admin)    │        │
│                           └─────────────────────┘        │
└──────────────────────────────────────────────────────────┘
```

---

## 🔐 Camadas de Segurança

A aplicação implementa **6 camadas de defesa em profundidade**:

### Camada 1 — Restrição por IP VPN (Whitelist)

Toda requisição é interceptada antes de qualquer processamento. Apenas IPs da sub-rede `100.96.x.x` (atribuídos pelo CloudConnexa) são aceitos. Qualquer IP externo recebe um erro `403 Forbidden` imediato.

### Camada 2 — Autenticação por Login

Mesmo dentro da VPN, o usuário precisa se autenticar com credenciais válidas. As senhas são armazenadas com hash SHA-256. As sessões expiram automaticamente após 30 minutos de inatividade.

### Camada 3 — Controle de Acesso por Papel (RBAC)

Cada usuário possui um papel com permissões específicas, aplicando o princípio de menor privilégio:

| Papel | Dashboard | API Projetos | Logs | Configurações |
|-------|:---------:|:------------:|:----:|:-------------:|
| **Admin** | ✅ | ✅ | ✅ | ✅ |
| **Professor** | ✅ | ✅ | ✅ | ❌ |
| **Usuário** | ✅ | ❌ | ❌ | ❌ |

### Camada 4 — Rate Limiting

Proteção contra ataques de força bruta e negação de serviço:
- Máximo de **10 requisições por minuto** por IP
- Máximo de **5 tentativas de login** — após exceder, o IP é bloqueado por **5 minutos**

### Camada 5 — Headers de Segurança HTTP

Headers de hardening aplicados em todas as respostas:

| Header | Proteção |
|--------|----------|
| `X-Frame-Options: DENY` | Impede clickjacking |
| `X-Content-Type-Options: nosniff` | Previne MIME sniffing |
| `X-XSS-Protection: 1; mode=block` | Ativa filtro XSS do navegador |
| `Content-Security-Policy` | Restringe origens de conteúdo |
| `Strict-Transport-Security` | Força uso de HTTPS |
| `Referrer-Policy` | Controla vazamento de referrer |
| `Cache-Control: no-store` | Impede cache de dados sensíveis |

### Camada 6 — Logging de Auditoria

Todos os eventos são registrados no arquivo `access_audit.log`:
- Logins bem-sucedidos e falhos
- Acessos a cada rota
- Bloqueios por IP não autorizado
- Bloqueios por rate limiting
- Logouts e expiração de sessão

---

## 📋 Pré-requisitos

- **Python 3.10** ou superior
- **pip** (gerenciador de pacotes Python)
- **OpenVPN Connect** instalado e conectado ao CloudConnexa
- Conta configurada no **OpenVPN CloudConnexa** (plano gratuito — até 3 usuários)

---

## ⚙️ Instalação

**1. Clone o repositório:**

```bash
git clone https://github.com/seu-usuario/cybershield-soc.git
cd cybershield-soc
```

**2. Crie um ambiente virtual (recomendado):**

```bash
python3 -m venv venv
source venv/bin/activate        # macOS / Linux
# venv\Scripts\activate         # Windows
```

**3. Instale as dependências:**

```bash
pip install -r requirements.txt
```

**4. Descubra seu IP VPN:**

```bash
# macOS
ifconfig | grep -A 5 "utun"

# Linux
ip addr show tun0

# Windows
ipconfig
```

Procure o IP na faixa `100.96.x.x`.

**5. Configure o IP no `app.py`:**

Abra o arquivo e edite a linha:

```python
VPN_HOST = '100.96.1.2'    # ← Troque pelo seu IP VPN
```

---

## 🚀 Uso

### Iniciar o servidor

Certifique-se de que a VPN está conectada, depois:

```bash
python3 app.py
```

Saída esperada:

```
=================================================================
  CyberShield SOC — Servidor Flask Seguro
=================================================================
  Host:          100.96.1.2:5000
  Sub-rede VPN:  100.96.x.x (whitelist)
  Rate Limit:    10 req / 60s
  Login Limit:   5 tentativas (bloqueio 300s)
  Log de audit:  access_audit.log
-----------------------------------------------------------------
  Usuários cadastrados:
    → admin (papel: admin)
    → professor (papel: professor)
    → usuario (papel: usuario)
-----------------------------------------------------------------
  Camadas de segurança ativas:
    1. Restrição por IP VPN (whitelist)
    2. Autenticação por login (sessão)
    3. RBAC — Controle por papel
    4. Rate limiting (anti brute force)
    5. Headers HTTP de segurança
    6. Logging de auditoria
=================================================================
```

### Acessar a aplicação

Abra o navegador e acesse:

```
http://100.96.1.2:5000
```

### Credenciais de acesso

| Usuário | Senha | Papel |
|---------|-------|-------|
| `admin` | `Admin@2026` | Administrador |
| `professor` | `Prof@2026` | Professor |
| `usuario` | `User@2026` | Usuário Padrão |

### Endpoints disponíveis

| Rota | Método | Permissão | Descrição |
|------|--------|-----------|-----------|
| `/` | GET | dashboard | Dashboard principal (SOC) |
| `/login` | GET/POST | público | Tela de autenticação |
| `/logout` | GET | autenticado | Encerra a sessão |
| `/api/status` | GET | autenticado | Status do servidor (JSON) |
| `/api/projetos` | GET | api | Lista de projetos (JSON) |
| `/api/logs` | GET | logs | Últimos 50 eventos de auditoria |
| `/api/security-info` | GET | autenticado | Detalhes das camadas de segurança |

---

## 📁 Estrutura do Projeto

```
cybershield-soc/
│
├── .gitignore              # Arquivos ignorados pelo Git
├── .gitattributes          # Tratamento de arquivos pelo Git
├── requirements.txt        # Dependências Python
├── README.md               # Este arquivo
│
├── app.py                  # Servidor Flask (6 camadas de segurança)
├── dashboard.html          # Interface do dashboard SOC
│
└── access_audit.log        # Log de auditoria (gerado automaticamente)
```

---

## 🧪 Testes

### Teste 1 — Inacessibilidade sem VPN

1. Desconecte a VPN
2. Tente acessar `http://100.96.1.2:5000` no navegador
3. **Resultado esperado:** timeout / conexão recusada

### Teste 2 — Acesso pelo Professor

1. Conecte na VPN como Professor (com MFA)
2. Acesse `http://100.96.1.2:5000`
3. Faça login com `professor` / `Prof@2026`
4. **Resultado esperado:** dashboard carrega normalmente
5. Acesse `/api/projetos` → JSON com dados
6. Acesse `/api/logs` → logs de auditoria

### Teste 3 — Acesso pelo Usuário (permissões restritas)

1. Conecte na VPN como Usuário
2. Faça login com `usuario` / `User@2026`
3. **Resultado esperado:** dashboard carrega
4. Tente acessar `/api/projetos` → **403 Acesso Negado**
5. Tente acessar `/api/logs` → **403 Acesso Negado**

### Teste 4 — Rate Limiting

1. Envie mais de 10 requisições rápidas (F5 repetido)
2. **Resultado esperado:** erro 429 (limite excedido)

### Teste 5 — Brute Force no Login

1. Tente logar 5 vezes com senha errada
2. **Resultado esperado:** IP bloqueado por 5 minutos

### Teste 6 — Verificação dos Headers

```bash
curl -I http://100.96.1.2:5000/login
```

**Resultado esperado:** headers de segurança presentes na resposta.

---

## 🔗 Tecnologias Utilizadas

| Tecnologia | Finalidade |
|------------|------------|
| **Python 3** | Linguagem principal |
| **Flask** | Framework web para o servidor |
| **OpenVPN CloudConnexa** | Infraestrutura VPN com MFA |
| **Cyber Shield** | Filtragem DNS e bloqueio de categorias |
| **SHA-256** | Hash de senhas |
| **HTML/CSS/JS** | Interface do dashboard SOC |

---

## 📄 Licença

Este projeto foi desenvolvido exclusivamente para fins acadêmicos, como parte do Trabalho Discente Final da disciplina de Cibersegurança Aplicada — UPF 2026.
