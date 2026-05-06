import time
import json
import os
from datetime import datetime
from memory.chroma_store import get_log_collection
from orchestrator import run_soc_pipeline

POLL_INTERVAL   = 60
SEVERITY_CUTOFF = 7
INVESTIGATED    = "investigated.json"


def load_investigated() -> set:
    if os.path.exists(INVESTIGATED):
        with open(INVESTIGATED) as f:
            return set(json.load(f))
    return set()


def save_investigated(ids: set):
    with open(INVESTIGATED, "w") as f:
        json.dump(list(ids), f)


def fetch_new_high_severity(investigated: set) -> list:
    col = get_log_collection()
    results = col.query(
        query_texts=["attack lateral movement brute force c2 beacon high severity"],
        n_results=50,
        where={"severity": "high"}
    )
    docs  = results["documents"][0] if results["documents"] else []
    metas = results["metadatas"][0]  if results["metadatas"] else []
    ids   = results["ids"][0]        if results["ids"] else []

    new_alerts = []
    for doc, meta, log_id in zip(docs, metas, ids):
        if log_id not in investigated and meta.get("attack_type", "") != "normal_traffic":
            new_alerts.append({"id": log_id, "text": doc, "meta": meta})
    return new_alerts


def run(interval: int = POLL_INTERVAL):
    print(f"[PipelineRunner] 🚀 Started — polling every {interval}s")
    print(f"[PipelineRunner] Severity cutoff: {SEVERITY_CUTOFF}/10\n")

    while True:
        now = datetime.now().strftime("%H:%M:%S")
        investigated = load_investigated()
        alerts = fetch_new_high_severity(investigated)

        if not alerts:
            print(f"[{now}] No new alerts. Sleeping {interval}s...")
        else:
            print(f"[{now}] Found {len(alerts)} new alert(s)!")
            for alert in alerts:
                print(f"\n  → Investigating: {alert['text'][:80]}...")
                try:
                    run_soc_pipeline(alert["text"])
                    investigated.add(alert["id"])
                    save_investigated(investigated)
                    print(f"  ✓ Done — alert queued to HITL dashboard if severity >= 8")
                except Exception as e:
                    print(f"  ✗ Error: {e}")

        time.sleep(interval)

if __name__ == "__main__":
    run()