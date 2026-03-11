# Security Agent — OWASP Code Analyzer 🔒

## Sobre o Projeto

Agente de IA para **Engenharia de Software para Segurança** que utiliza o padrão **ReAct (Reasoning and Acting)** para analisar código Python em busca de vulnerabilidades com base nos padrões OWASP.

O sistema opera em **duas fases**:

1. **Análise Estática Determinística** — 14 padrões regex pré-compilados detectam vulnerabilidades instantaneamente, com severidade e referência OWASP
2. **Agente ReAct com RAG** — LLM com raciocínio multi-step consulta a base de conhecimento OWASP para contexto adicional e sugestões de correção

### Stack Tecnológica

| Tecnologia | Função |
|---|---|
| **Python 3.9+** | Linguagem principal |
| **Streamlit** | Interface web interativa |
| **Ollama** | Inferência LLM local (llama3.1:8b) |
| **LangChain** | Framework ReAct agent com ferramentas |
| **ChromaDB** | Banco vetorial para base de conhecimento OWASP |
| **Sentence Transformers** | Embeddings de texto (all-MiniLM-L6-v2) |

---

## Arquitetura

```
Streamlit UI
├── Home Page (entrada de código → análise em 2 fases)
│   ├── Phase 1: Análise estática (regex, instantânea)
│   └── Phase 2: Agente ReAct (LLM + RAG)
└── Admin Page (autenticada: upload/treino/reset da KB)

Agente ReAct (LangChain AgentExecutor)
├── Ferramentas (4):
│   ├── analyze_code      — análise estática com 14 padrões regex
│   ├── search_owasp_kb   — busca vetorial na base OWASP
│   ├── get_cve_details   — lookup de CVE/CWE específicos
│   └── search_remediation — busca direcionada para correções
├── Retriever singleton (lru_cache)
├── Streaming callbacks → UI em tempo real
└── Ollama llama3.1:8b (temperature=0)

Armazenamento: ChromaDB (KB vetorial) + knowledge-base/ (documentos fonte)
```

---

## Como Executar

### Pré-requisitos

- Python 3.9+
- [Ollama](https://ollama.com) instalado e rodando

### 1. Clonar o Repositório

```bash
git clone https://github.com/lexcesar/drmec-x.git
cd drmec-x
```

### 2. Criar Ambiente Virtual

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
```

### 3. Instalar Dependências

```bash
pip install -r requirements.txt
```

### 4. Baixar o Modelo LLM

```bash
ollama pull llama3.1:8b
```

Certifique-se de que o serviço Ollama está rodando.

### 5. Iniciar a Aplicação

```bash
streamlit run streamlit_app.py
```

Acesse http://localhost:8501.

---

## Uso

### 1. Configurar Base de Conhecimento (Página Admin)

1. Acesse a página **Admin** pelo sidebar
2. Insira a senha (padrão: `admin`, configurável via `ADMIN_PASSWORD`)
3. Faça upload de documentos OWASP (PDF, Markdown ou texto)
4. Clique em **"Train System with Current Data"**

### 2. Analisar Código (Página Home)

1. Acesse a página **Home**
2. Cole seu código Python na área de texto
3. Clique em **"Analyze Security"**
4. Veja os resultados em duas fases:
   - **Phase 1**: Tabela com vulnerabilidades detectadas (severidade, linha, OWASP)
   - **Phase 2**: Análise do agente ReAct com contexto da base OWASP

### Exemplo de Código para Teste

```python
import os
import pickle
import random

password = "admin123"
DEBUG = True

def get_user(user_id):
    query = "SELECT * FROM users WHERE id=" + user_id
    return db.execute(query)

def run_command(cmd):
    os.system(cmd)

def load_data(raw_bytes):
    return pickle.loads(raw_bytes)

def generate_token():
    return random.randint(1000, 9999)

def fetch_data(url):
    requests.get(url, verify=False)

config = yaml.load(open("config.yml"))
```

---

## Padrão ReAct (Reasoning and Acting)

O agente segue um loop de raciocínio multi-step:

```
Thought  → "Devo verificar este código para padrões de injeção SQL"
Action   → analyze_code (detecção estática de padrões)
Observe  → "Encontrada concatenação SQL na linha 10"
Thought  → "Vou buscar os padrões OWASP para esta vulnerabilidade"
Action   → search_owasp_kb (busca vetorial nos documentos de segurança)
Observe  → "OWASP A03:2021 - Injection..."
Thought  → "Agora preciso buscar orientação de correção"
Action   → search_remediation (busca direcionada para remediação)
Observe  → "Use queries parametrizadas..."
Answer   → Relatório estruturado com findings + correções
```

---

## Ferramentas do Agente

| Ferramenta | Tipo | O que faz (que o LLM não consegue sozinho) |
|---|---|---|
| `analyze_code` | Determinístico | Matching de regex para 14 padrões de vulnerabilidade |
| `search_owasp_kb` | RAG | Busca por similaridade vetorial nos documentos de segurança |
| `get_cve_details` | RAG | Lookup de identificadores CVE/CWE específicos na KB |
| `search_remediation` | RAG | Busca direcionada para seções de correção/mitigação |

### Padrões de Vulnerabilidade Detectados (Phase 1)

| Padrão | Severidade | OWASP |
|---|---|---|
| Credenciais hardcoded (password, api_key, token) | 🟠 High | A07:2021 |
| Funções perigosas (exec, eval, compile) | 🔴 Critical | A03:2021 |
| SQL Injection (concatenação/format) | 🔴 Critical | A03:2021 |
| Command Injection (subprocess shell=True) | 🔴 Critical | A03:2021 |
| Desserialização insegura (pickle) | 🟠 High | A08:2021 |
| YAML load sem Loader | 🟠 High | A08:2021 |
| Execução de comando OS (os.system/popen) | 🔴 Critical | A03:2021 |
| SSL verificação desabilitada | 🟠 High | A02:2021 |
| Hash fraco (MD5/SHA1) | 🟠 High | A02:2021 |
| Random não-criptográfico | 🟠 High | A02:2021 |
| XSS (innerHTML/document.write) | 🔴 Critical | A03:2021 |
| URL HTTP sem criptografia | 🟠 High | A02:2021 |
| Debug mode habilitado | 🟡 Medium | A05:2021 |
| CORS wildcard (*) | 🟡 Medium | A05:2021 |

---

## Segurança da Aplicação

O próprio sistema implementa medidas de segurança:

- **Mitigação de Prompt Injection**: delimitadores `<USER_CODE>` + sanitização de tokens ReAct
- **Autenticação no Admin**: senha configurável via variável de ambiente
- **Sanitização de uploads**: validação de nome de arquivo contra path traversal
- **Validação de extensão**: apenas PDF, MD e TXT aceitos (server-side)
- **Mensagens de erro genéricas**: sem exposição de detalhes internos
- **Timeout do agente**: limite de 120s e 6 iterações

---

## Estrutura de Arquivos

```
drmec-x/
├── streamlit_app.py        # Ponto de entrada
├── config.py               # Configuração centralizada (pathlib)
├── static_analysis.py      # Padrões regex + analyze_code (sem dependências LangChain)
├── tools.py                # 3 ferramentas RAG + retriever singleton
├── agent.py                # Agente ReAct + prompt com few-shot
├── pages/
│   ├── home.py             # UI de análise (2 fases)
│   └── admin.py            # Administração da KB (autenticada)
├── knowledge-base/         # Documentos OWASP (fonte)
├── chroma_db/              # Banco vetorial ChromaDB (gerado)
├── tests/
│   ├── test_analyze_code.py  # 27 testes dos padrões regex
│   └── test_tools.py         # 11 testes das ferramentas RAG (mock)
└── requirements.txt
```

---

## Testes

```bash
python3 -m pytest tests/ -v
```

38 testes unitários cobrindo:
- Todos os 14 padrões de vulnerabilidade (positivos e negativos)
- Formatação de documentos recuperados
- Ferramentas RAG com retriever mockado
- Edge cases (código vazio, input limpo, múltiplas vulnerabilidades)

---

## Licença

Proprietary License - All Rights Reserved. Este software é propriedade exclusiva de Alexander Costa. Cópia, modificação, distribuição e uso comercial são estritamente proibidos sem autorização prévia por escrito. Consulte o arquivo [LICENSE](LICENSE) para detalhes.

## Contato

Alexander Costa - https://alexcesar.com
