import sys
from log_generator import generate_zeek_log, generate_syslog, generate_windows_event, generate_batch
from memory.chroma_store import add_log
import random

def format_log(log: dict) -> tuple[str, dict]:
    source = log.get("source", "unknown")

    if source == "zeek":
        text = (
            f"[ZEEK] {log['timestamp']} | {log['src_ip']} → {log['dst_ip']}:{log['dst_port']} "
            f"| Protocol: {log['protocol']} | Attack: {log['attack_type']} "
            f"| Tactic: {log['tactic']} | Technique: {log['technique']} "
            f"| Bytes: {log['bytes_sent']} | Severity: {log['severity']}"
        )
        metadata = {
            "source":      "zeek",
            "source_ip":   log["src_ip"],
            "dest_ip":     log["dst_ip"],
            "attack_type": log["attack_type"],
            "tactic":      log["tactic"],
            "technique":   log["technique"],
            "severity":    log["severity"],
            "timestamp":   log["timestamp"],
        }

    elif source == "syslog":
        text = (
            f"[SYSLOG] {log['timestamp']} | Host: {log['host']} "
            f"| Message: {log['message']} | Severity: {log['severity']}"
        )
        metadata = {
            "source":    "syslog",
            "source_ip": "unknown",
            "dest_ip":   "unknown",
            "host":      log["host"],
            "severity":  log["severity"],
            "timestamp": log["timestamp"],
        }

    elif source == "windows_event":
        text = (
            f"[WINDOWS] {log['timestamp']} | EventID: {log['event_id']} "
            f"| {log['description']} | User: {log['user']} | Host: {log['host']} "
            f"| SrcIP: {log['src_ip']} | Tactic: {log['tactic']} | Severity: {log['severity']}"
        )
        metadata = {
            "source":    "windows_event",
            "source_ip": log["src_ip"],
            "dest_ip":   "unknown",
            "event_id":  str(log["event_id"]),
            "tactic":    log["tactic"],
            "severity":  log["severity"],
            "timestamp": log["timestamp"],
        }

    else:
        text = str(log)
        metadata = {"source": "unknown", "timestamp": log.get("timestamp", "")}

    return text, metadata


def ingest_logs(count: int = 100):
    print(f"[Ingestor] Generating and ingesting {count} logs into ChromaDB...")
    batch = generate_batch(count)
    for i, log in enumerate(batch):
        text, metadata = format_log(log)
        add_log(text, metadata)
        if (i + 1) % 20 == 0:
            print(f"  → {i+1}/{count} ingested")
    print(f"[Ingestor] ✅ Done. {count} logs pushed to ChromaDB.")


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    ingest_logs(count)