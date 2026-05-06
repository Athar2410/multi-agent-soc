# 🛡️ Multi-Agent SOC (Security Operations Center)

An autonomous, LLM-powered Security Operations Center built with CrewAI, ChromaDB, and Streamlit. Detects, investigates, and triages cybersecurity incidents using a pipeline of specialized AI agents — with a human-in-the-loop approval gate for high-severity alerts.

---

## 🏗️ Architecture

```
Log Sources (Zeek / Syslog / Windows Events)
            ↓
      ingestor.py
    (ML classification + ChromaDB vector store)
            ↓
     pipeline_runner.py
    (polls for new high-severity alerts every 60s)
            ↓
      orchestrator.py
    ┌─────────────────────────────────────────┐
    │  Phase 1 — Triage                       │
    │  assign_severity() → attack type + score│
    │                                         │
    │  Phase 2 — Threat Hunting               │
    │  query_vector_db() → related logs       │
    │  mitre_lookup()    → ATT&CK mapping     │
    │  enrich_ioc()      → AbuseIPDB + VT     │
    │                                         │
    │  Phase 3 — Forensics                    │
    │  timeline_reconstruct() → event chain   │
    │  lateral_movement_check() → spread      │
    │                                         │
    │  Phase 4 — ReporterAgent (CrewAI LLM)  │
    │  → Structured Markdown incident report  │
    └─────────────────────────────────────────┘
            ↓ severity >= 8?
      hitl_queue.db (SQLite HITL gate)
            ↓
      dashboard.py (Streamlit)
    ┌──────────────────────────────┐
    │  🔴 Pending Approvals        │
    │  📋 Alert History            │
    │  📊 SOC Metrics              │
    └──────────────────────────────┘
```

---

## 🤖 Agents

| Agent | Role | Tools |
|---|---|---|
| **TriageAgent** | Classifies attack type and severity score | `assign_severity` |
| **HunterAgent** | Semantic log search + IOC enrichment + MITRE mapping | `query_vector_db`, `enrich_ioc`, `mitre_lookup` |
| **ForensicsAgent** | Attack timeline reconstruction + lateral movement detection | `timeline_reconstruct`, `lateral_movement_check` |
| **ReporterAgent** | Synthesizes all findings into a structured incident report | None (reasoning only) |

---

## 🧰 Tech Stack

| Component | Technology |
|---|---|
| Agent Framework | CrewAI + Ollama (llama3.1 — fully local) |
| Vector Database | ChromaDB (semantic log search) |
| ML Classifier | Random Forest trained on NSL-KDD dataset |
| Threat Intelligence | AbuseIPDB API + VirusTotal API |
| Threat Knowledge Base | MITRE ATT&CK Enterprise (local JSON) |
| HITL Queue | SQLite |
| Analyst Dashboard | Streamlit |
| Log Sources | Zeek, Syslog, Windows Event Logs |

---

## 🚀 Setup

### 1. Clone and install dependencies

```bash
git clone https://github.com/Atharva2410/multiagentsoc.git
cd multiagentsoc
python -m venv soc_venv
soc_venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start Ollama with llama3.1

```bash
ollama pull llama3.1
ollama serve
```

### 3. Download MITRE ATT&CK data

```powershell
iwr "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" -OutFile "mitre_attack.json"
```

### 4. Add API keys

Create a `.env` file:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

### 5. Generate logs and ingest

```bash
python log_generator.py
python ingestor.py
```

### 6. Run the pipeline

```bash
python orchestrator.py
# or continuous mode:
python pipeline_runner.py
```

### 7. Launch the dashboard

```bash
streamlit run dashboard.py
```

---

## 📊 Dashboard Features

- **Pending Approvals** — review reports, approve/reject/escalate alerts
- **Alert History** — full audit trail with analyst + timestamp
- **SOC Metrics** — KPIs, attack distribution, MTTR, false positive rate

---

## 🔬 ML Classification Model

Random Forest trained on NSL-KDD dataset:

| Category | Description |
|---|---|
| `normal` | Legitimate traffic |
| `dos` | Denial of Service |
| `probe` | Network reconnaissance |
| `r2l` | Remote to Local |
| `u2r` | User to Root — privilege escalation |
| `lateral_movement` | SMB/RDP spread (T1021) |
| `c2_beacon` | Command & Control |
| `ssh_bruteforce` | Brute force over SSH |
| `port_scan` | Network discovery (T1046) |

---

## 🗂️ Project Structure

```
multiagentsoc/
├── soc_agents/
│   ├── triage_agent.py
│   ├── hunter_agent.py
│   ├── forensics_agent.py
│   └── reporter_agent.py
├── tools/
│   └── agent_tools.py
├── memory/
│   └── chroma_store.py
├── hitl/
│   ├── queue_manager.py
│   └── auto_response.py
├── orchestrator.py
├── pipeline_runner.py
├── dashboard.py
├── metrics.py
├── ingestor.py
├── log_generator.py
└── requirements.txt
```

---

## 🔑 Key Design Decisions

**Why pre-run tools instead of full ReAct?**
Local LLMs (llama3.1 8B) loop on multi-tool tasks. Pre-executing deterministic tools in Python and injecting structured results makes the pipeline reliable without a 70B model.

**Why ChromaDB?**
Enables semantic log search — finds related events even with different phrasing, unlike exact-match SIEM queries.

**Why SQLite for HITL?**
Zero-config and portable. Production would use Redis/RabbitMQ with auto-escalation timeouts.

---

## 🛣️ Roadmap

- [ ] Real Zeek log ingestion from Kali VM
- [ ] Slack/email notifications for approvals
- [ ] Auto-escalation after 30min timeout
- [ ] Docker Compose deployment
- [ ] Real firewall API (pfSense/iptables)

---

## 📄 License

MIT

---

## 👤 Author

Built by **Atharva Amle** — [GitHub: Atharva2410](https://github.com/Atharva2410)