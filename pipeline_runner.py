import time, os, json
from datetime import datetime
from memory.chroma_store import get_log_collection
from orchestrator import run_soc_pipeline

REPORTS_DIR = "reports"
INVESTIGATED_FILE = "investigated.json"
os.makedirs(REPORTS_DIR, exist_ok=True)

def load_investigated() -> set:
    if os.path.exists(INVESTIGATED_FILE):
        with open(INVESTIGATED_FILE) as f:
            return set(json.load(f))
    return set()

def save_investigated(ids: set):
    with open(INVESTIGATED_FILE, "w") as f:
        json.dump(list(ids), f)

def get_uninvestigated_alerts(investigated: set) -> list:
    col = get_log_collection()
    results = col.query(
        query_texts=["high severity attack lateral movement brute force exfiltration"],
        n_results=50,
        where={"severity": "high"}
    )
    docs   = results["documents"][0] if results["documents"] else []
    metas  = results["metadatas"][0]  if results["metadatas"] else []
    ids    = results["ids"][0]        if results["ids"] else []

    alerts = []
    for doc, meta, log_id in zip(docs, metas, ids):
        if log_id not in investigated:
            alerts.append({"id": log_id, "text": doc, "meta": meta})
    return alerts

def save_report(alert_id: str, report: str, meta: dict):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{REPORTS_DIR}/report_{ts}_{alert_id[:8]}.md"
    with open(fname, "w") as f:
        f.write(f"# Incident Report\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}\n")
        f.write(f"**Source IP:** {meta.get('source_ip', 'unknown')}\n")
        f.write(f"**Attack Type:** {meta.get('attack_type', 'unknown')}\n\n")
        f.write(report if isinstance(report, str) else str(report))
    print(f"  [✓] Report saved → {fname}")

def run_pipeline(interval_seconds: int = 60):
    print(f"[PipelineRunner] Starting — polling every {interval_seconds}s for new high-severity alerts...\n")
    while True:
        investigated = load_investigated()
        alerts = get_uninvestigated_alerts(investigated)

        if not alerts:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] No new alerts. Waiting {interval_seconds}s...")
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(alerts)} new alert(s) to investigate.")
            for alert in alerts:
                print(f"\n  → Investigating: {alert['text'][:100]}...")
                try:
                    report = run_soc_pipeline(alert["text"])
                    save_report(alert["id"], report, alert["meta"])
                    investigated.add(alert["id"])
                    save_investigated(investigated)
                except Exception as e:
                    print(f"  [!] Error on alert {alert['id'][:8]}: {e}")

        time.sleep(interval_seconds)

if __name__ == "__main__":
    run_pipeline(interval_seconds=60)