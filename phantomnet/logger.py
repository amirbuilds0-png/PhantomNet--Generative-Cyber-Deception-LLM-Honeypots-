import json
import os
import re
import threading
import time

# Lightweight MITRE ATT&CK tagging (rule based; extended in the second half of the project)
ATTACK_RULES = [
    (r"\b(wget|curl|tftp|scp)\b", "T1105"),            # Ingress Tool Transfer
    (r"/etc/(passwd|shadow)", "T1003.008"),            # OS Credential Dumping
    (r"\b(uname|lscpu|lsb_release|hostnamectl)\b|/proc/cpuinfo", "T1082"),       # System Information Discovery
    (r"\b(whoami|id|w|who|last)\b", "T1033"),          # System Owner/User Discovery
    (r"\b(ifconfig|netstat)\b|\bip a|\bss -", "T1016"),                           # Network Config Discovery
    (r"\bps\b|\btop\b", "T1057"),                      # Process Discovery
    (r"\bcrontab\b|/etc/cron", "T1053.003"),           # Cron persistence
    (r"authorized_keys", "T1098.004"),                 # SSH Authorized Keys
    (r"chmod\s+(\+x|[0-7]*7[0-7]*)", "T1222.002"),     # File permission modification
    (r"history\s+-c|unset HISTFILE|rm .*bash_history", "T1070.003"),             # Clear command history
    (r"xmrig|minerd|stratum\+tcp|cpuminer", "T1496"),  # Resource hijacking
    (r"\bnc\b|ncat|bash -i|/dev/tcp/", "T1059.004"),   # Unix shell / reverse shell
    (r"\b(iptables|ufw)\b", "T1562.004"),              # Impair defenses
    (r"\b(useradd|adduser|passwd)\b", "T1136.001"),    # Create local account
]
_COMPILED = [(re.compile(p), t) for p, t in ATTACK_RULES]


def tag_techniques(cmd: str) -> list:
    return sorted({t for rx, t in _COMPILED if rx.search(cmd)})


class EventLogger:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: str, **fields):
        rec = {"ts": round(time.time(), 3), "event": event, **fields}
        with self._lock, open(self.path, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
