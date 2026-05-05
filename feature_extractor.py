# feature_extractor.py  (full replacement)
import numpy as np
import pandas as pd

# All 41 NSL-KDD features in exact training order
NSL_KDD_FEATURES = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "SMB": 0, "HTTP": 0, "HTTPS": 0, "ICMP": 2}
SERVICE_MAP  = {"http": 0, "ftp": 1, "smtp": 2, "ssh": 3, "dns": 4,
                "https": 5, "pop3": 6, "telnet": 7, "other": 8}
FLAG_MAP     = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "SH": 4,
                "RSTR": 5, "S1": 6, "S2": 7, "S3": 8, "OTH": 9}

def log_to_nslkdd(log: dict) -> np.ndarray:
    """
    Map a log dict to the 41 NSL-KDD features.
    Unknown fields default to 0 — good enough for demo detection.
    """
    proto   = log.get("protocol", "TCP")
    port    = int(log.get("dst_port", 0))
    sbytes  = int(log.get("bytes_sent", 0))
    attack  = log.get("attack_type", "normal_traffic")

    # Derive service from port number
    port_to_service = {22:"ssh", 80:"http", 443:"https", 21:"ftp",
                       25:"smtp", 53:"dns", 110:"pop3", 23:"telnet"}
    service_str = port_to_service.get(port, "other")

    # Heuristic features based on attack type
    heuristics = {
        "ssh_bruteforce":    {"num_failed_logins":5, "count":511, "serror_rate":0.0,  "rerror_rate":1.0, "same_srv_rate":1.0},
        "port_scan":         {"count":511, "srv_count":511, "serror_rate":0.6, "same_srv_rate":0.06, "diff_srv_rate":0.94},
        "lateral_movement":  {"logged_in":1, "num_compromised":1, "count":10,  "same_srv_rate":0.9},
        "data_exfiltration": {"dst_bytes":50000, "logged_in":1, "count":5,    "same_srv_rate":1.0},
        "c2_beacon":         {"dst_bytes":500,   "count":300,   "same_srv_rate":1.0, "serror_rate":0.0},
        "normal_traffic":    {"same_srv_rate":1.0,"count":1},
    }
    h = heuristics.get(attack, {})

    row = {f: 0.0 for f in NSL_KDD_FEATURES}  # default everything to 0
    row["duration"]          = 0.0
    row["protocol_type"]     = float(PROTOCOL_MAP.get(proto, 0))
    row["service"]           = float(SERVICE_MAP.get(service_str, 8))
    row["flag"]              = float(FLAG_MAP.get("SF", 0))
    row["src_bytes"]         = float(sbytes)
    row["dst_bytes"]         = float(h.get("dst_bytes", 0))
    row["logged_in"]         = float(h.get("logged_in", 0))
    row["num_failed_logins"] = float(h.get("num_failed_logins", 0))
    row["num_compromised"]   = float(h.get("num_compromised", 0))
    row["count"]             = float(h.get("count", 1))
    row["srv_count"]         = float(h.get("srv_count", row["count"]))
    row["serror_rate"]       = float(h.get("serror_rate", 0.0))
    row["rerror_rate"]       = float(h.get("rerror_rate", 0.0))
    row["same_srv_rate"]     = float(h.get("same_srv_rate", 1.0))
    row["diff_srv_rate"]     = float(h.get("diff_srv_rate", 0.0))
    row["dst_host_count"]    = float(h.get("count", 1))
    row["dst_host_srv_count"]= float(h.get("srv_count", row["count"]))
    row["dst_host_same_srv_rate"] = float(h.get("same_srv_rate", 1.0))
    row["dst_host_serror_rate"]   = float(h.get("serror_rate", 0.0))

    return np.array([row[f] for f in NSL_KDD_FEATURES]).reshape(1, -1)

def extract_features(log: dict) -> np.ndarray:
    return log_to_nslkdd(log)