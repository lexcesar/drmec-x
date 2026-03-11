---
title: "feat: Security Agent with ReAct - OWASP Code Analyzer"
type: feat
status: completed
date: 2026-03-10
deepened: 2026-03-10
---

# feat: Security Agent with ReAct - OWASP Code Analyzer

## Enhancement Summary

**Deepened on:** 2026-03-10
**Agents used:** 8 reviewers + Context7 (LangChain, ChromaDB)

### Key Improvements
1. Cache retriever as singleton (`lru_cache`) — eliminates 5-15s wasted per analysis
2. Replace fake tools with real tools — every tool must do retrieval or computation
3. Add prompt injection mitigation — `<USER_CODE>` delimiters
4. Add few-shot examples to ReAct prompt — essential for local models
5. Use `st.text_area` + `st.code()` instead of `streamlit-ace` — simpler
6. Scope to Python only — depth over breadth
7. Add streaming callbacks — show ReAct steps in real-time
8. Use `pathlib.Path` — reliable path resolution

## Overview

Adapt the existing Dr. Mec X into a **Security Engineering AI Agent** using **ReAct (Reasoning and Acting)** to analyze code for vulnerabilities based on OWASP standards.

**Tema 8: Agente de IA para Engenharia de Software para Segurança**

## Architecture

```
Streamlit UI
├── Admin Page (upload/train/reset KB)
└── Security Review (code input → ReAct agent → structured results)

ReAct Agent (LangChain)
├── Tools (4 real tools):
│   ├── search_owasp_kb (RAG retrieval)
│   ├── analyze_code (regex patterns — deterministic)
│   ├── get_cve_details (RAG retrieval)
│   └── search_remediation (targeted RAG retrieval)
├── Singleton retriever (lru_cache)
├── Streaming callbacks → UI
└── Ollama llama3 (temperature=0)

Storage: ChromaDB (OWASP KB) + knowledge-base/ (source docs)
```

## Tool Design (Revised from Research)

| Tool | Type | What it does the LLM cannot |
|---|---|---|
| `search_owasp_kb` | RAG | Vector similarity search on security standards |
| `analyze_code` | Deterministic | Regex pattern matching for vulnerability indicators |
| `get_cve_details` | RAG | Lookup specific CVE/CWE identifiers from KB |
| `search_remediation` | RAG | Search KB for fix/mitigation sections |

**Removed:** `suggest_fix` (LLM-calling-LLM), `generate_security_policy` (LLM-calling-LLM)

## Implementation Phases

### Phase 1: Config (`config.py`)
- `pathlib.Path` for all paths (resolve relative to `__file__`)
- Module-level constants (no dotenv)
- All shared values: paths, model names, RAG params

### Phase 2: Agent + Tools (`agent.py`, `tools.py`)
- `create_react_agent` + `AgentExecutor` from LangChain
- Custom prompt with few-shot trajectory example
- `<USER_CODE>` delimiters for prompt injection mitigation
- `temperature=0`, `handle_parsing_errors=True`, `max_iterations=6`
- Singleton retriever via `@lru_cache`
- `invalidate_retriever_cache()` for admin reindexing

### Phase 3: Admin Page (`pages/admin.py`)
- `knowledge-base/` directory, English UI
- PDF/MD/TXT support, `with st.spinner()` context manager
- No `db.persist()` (ChromaDB 1.0+ auto-persists)
- Cache invalidation after training

### Phase 4: Home Page (`pages/home.py`)
- `st.text_area` for code input, `st.code()` for output
- Python-scoped (no language selector)
- Streaming ReAct callback shows steps in real-time
- Structured results in expanders + source attribution

### Phase 5: Knowledge Base + Entry Point
- Bundle OWASP Top 10 2021 PDF
- Fix `streamlit_app.py` entry point
- Update README

### Phase 6: Testing + Polish
- `tests/test_analyze_code.py` — regex pattern tests
- `tests/test_tools.py` — mocked retriever tests
- Error handling, clean requirements.txt

## Acceptance Criteria

- [x] ReAct agent with Thought → Action → Observation loop
- [x] 4 real tools (retrieval + computation, no LLM-wrapping)
- [x] Singleton retriever with `lru_cache`
- [x] Few-shot prompt with `<USER_CODE>` delimiters
- [x] Streaming ReAct steps in UI
- [x] `pathlib.Path` config, no dotenv
- [x] Admin: upload/train/reset with cache invalidation
- [x] Unit tests for `analyze_code` regex patterns (27 tests)
- [x] Error handling for Ollama offline, empty KB
- [ ] Full flow tested end-to-end (requires Ollama + knowledge base)

## Key Files

| File | Action |
|---|---|
| `config.py` | CREATE — pathlib config |
| `agent.py` | CREATE — ReAct agent + prompt |
| `tools.py` | CREATE — 4 tools + cached retriever |
| `pages/home.py` | MODIFY — streaming code review UI |
| `pages/admin.py` | MODIFY — KB management |
| `streamlit_app.py` | MODIFY — entry point |
| `tests/test_analyze_code.py` | CREATE — regex tests |
| `tests/test_tools.py` | CREATE — tool tests |
| `requirements.txt` | MODIFY — clean deps |
| `README.md` | MODIFY — new description |
