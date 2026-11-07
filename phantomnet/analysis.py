"""Turn the JSONL event log into a threat-intel style summary."""
import json
import sys
from collections import Counter


def load(path):
    with open(path) as fh:
        return [json.loads(l) for l in fh if l.strip()]


def summarize(events) -> str:
    cmds = [e for e in events if e["event"] == "command"]
    auths = [e for e in events if e["event"] == "auth"]
    sess = [e for e in events if e["event"] == "session_open"]
    tech = Counter(t for e in cmds for t in e.get("techniques", []))
    lat = sorted(e["latency_ms"] for e in cmds if e.get("source") == "llm")
    p = lambda q: lat[min(len(lat) - 1, int(len(lat) * q))] if lat else 0
    lines = ["# PhantomNet session summary", "",
             f"- Sessions: {len(sess)}  |  Commands: {len(cmds)}  |  Login attempts: {len(auths)}",
             f"- Unique source IPs: {len({e.get('src_ip') for e in sess})}",
             f"- Injection attempts: {sum('prompt_injection_attempt' in e['flags'] for e in cmds)}  |  Leaks blocked: {sum('leak_blocked' in e['flags'] for e in cmds)}",
             f"- LLM latency p50/p95 (ms): {p(.5)}/{p(.95)}", "", "## Top credentials"]
    lines += [f"- {u}:{pw} x{n}" for (u, pw), n in Counter((a['user'], a['password']) for a in auths).most_common(5)]
    lines += ["", "## Top commands"] + [f"- `{c}` x{n}" for c, n in Counter(e["cmd"] for e in cmds).most_common(10)]
    lines += ["", "## MITRE ATT&CK techniques observed"] + [f"- {t} x{n}" for t, n in tech.most_common()]
    return "\n".join(lines)


if __name__ == "__main__":
    print(summarize(load(sys.argv[1] if len(sys.argv) > 1 else "logs/phantomnet.jsonl")))
