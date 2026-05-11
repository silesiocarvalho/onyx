# Sariel v1.0.0 — Multi-Vendor Firewall Security Assessment Platform

A web-based security assessment platform with automated SSH + Management API audit,
AI-powered risk analysis (multi-provider via LiteLLM), manual review workbench,
and multi-format report generation (PDF, Excel, CSV, Word, Consulting Report).

---

## Supported Vendors

| Vendor | Connection | Checks |
|--------|-----------|--------|
| Check Point Gaia R82 | SSH (Clish) + Management API | CIS Benchmark v1.1.0 |
| Palo Alto PAN-OS 10+ | XML API + SSH fallback | CIS Benchmark v1.3.0 (82 checks) |

---

## Features

- **Automated audit** — SSH + Management API checks with live terminal output
- **AI enrichment** — per-finding risk analysis, attack chain correlation, executive narrative
- **Multi-provider AI** — Anthropic, OpenAI, Groq, Gemini, Ollama (local) — per-session key
- **Manual review workbench** — guided review for checks requiring human judgment
- **Playwright evidence capture** — screenshots from the firewall UI embedded in reports
- **Consulting Word report** — 7-section advisory narrative with priority matrix
- **4 export formats** — PDF, Excel, CSV, Word (technical) + Consulting Word
- **Session management** — multiple concurrent sessions, resume after restart
- **Credential safety** — all credentials Fernet-encrypted in-memory, never written to disk

---

## Quick Start

### 1. Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Clone and install

```bash
git clone https://github.com/silesiocarvalho/onyx.git
cd onyx
uv sync
```

### 3. (Optional) Install Playwright browser — for PAN-OS evidence capture only

```bash
uv run playwright install chromium
```

> **WSL users:** if you get `Exec format error`, Playwright's bundled Node can't run on WSL. Fix:
> ```bash
> # Install system Node
> sudo apt-get update && sudo apt-get install -y nodejs
>
> # Tell Playwright to use system Node instead of its bundled binary
> PLAYWRIGHT_NODEJS_PATH=$(which node) uv run playwright install chromium
>
> # Add to .env so evidence capture works at runtime too
> echo "PLAYWRIGHT_NODEJS_PATH=$(which node)" >> .env
> ```
> You can skip this step entirely — evidence capture is optional. All audit, AI, and export features work without it.

### 4. Start the server

```bash
bash start.sh
```

Open your browser: **http://localhost:8000**

---

## Usage

### Step 1 — Fill in the intake form

| Field | Description |
|-------|-------------|
| Vendor | Check Point or Palo Alto |
| Firewall IP | IP address reachable via SSH or HTTPS |
| Username / Password | Admin credentials |
| Management API Key | CP: SmartConsole API key · PA: XML API key (optional, falls back to SSH) |
| AI Provider + Key | Anthropic / OpenAI / Groq / Gemini / Ollama |
| Organization, Role, Industry | Context for the AI narrative |

Click **Start Assessment →**

### Step 2 — Automated audit

The live terminal streams check results in real time. After the audit completes,
AI enrichment runs three passes: per-finding risk → attack chains → executive narrative.

### Step 3 — Manual review

The workbench surfaces checks requiring human judgment with step-by-step guidance.
Complete each check and click **Save Finding**.

### Step 4 — Export

| Format | Description |
|--------|-------------|
| PDF | Cover page, exec summary, findings, attack chains |
| Excel | Color-coded findings workbook |
| CSV | Flat file for GRC tools |
| Word (Technical) | Editable technical report |
| Word (Consulting) | 7-section advisory report with priority matrix |

---

## Security

- Credentials are **never** stored on disk
- Credentials are **never** sent to the AI model
- All credentials are Fernet-encrypted in-memory for the session lifetime
- Sessions are destroyed on `DELETE /api/sessions/{id}` or server restart
- The tool operates in **read-only** mode — no changes are made to the firewall

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/sessions` | Create session |
| GET | `/api/sessions/{id}` | Session state + summary |
| POST | `/api/sessions/{id}/audit/start` | Start audit |
| GET | `/api/sessions/{id}/workbench` | Manual checks |
| POST | `/api/sessions/{id}/manual/{cid}` | Submit manual finding |
| POST | `/api/sessions/{id}/report/finalize` | Finalize report |
| GET | `/api/sessions/{id}/export/{fmt}` | Download PDF / Excel / CSV / docx |
| GET | `/api/sessions/{id}/export/consulting` | Download consulting Word report |
| DELETE | `/api/sessions/{id}` | Destroy session |
| WS | `/ws/{id}` | Real-time audit progress stream |

---

## Requirements

| Package | Purpose |
|---------|---------|
| fastapi + uvicorn | Web framework + ASGI server |
| paramiko | SSH client |
| playwright | UI evidence capture |
| litellm | Multi-provider AI |
| cryptography | Fernet credential encryption |
| reportlab | PDF generation |
| openpyxl | Excel generation |
| python-docx | Word generation |
