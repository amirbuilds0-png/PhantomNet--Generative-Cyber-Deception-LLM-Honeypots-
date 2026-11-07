"""Core decision engine: fast local path -> guard -> (cache) -> LLM -> sanitise -> log."""
import time
from dataclasses import dataclass

from .config import Config
from .guard import check_input, fallback_error, sanitize_output
from .llm import Backend, LLMError
from .logger import EventLogger, tag_techniques
from .persona import build_system
from .session import Session

IDEMPOTENT = {"uname", "id", "ps", "ifconfig", "ip", "uptime", "df", "free", "w", "lscpu", "lsb_release", "hostnamectl"}


@dataclass
class Result:
    output: str
    close: bool = False
    source: str = "llm"      # local | guard | cache | llm | fallback
    latency_ms: float = 0.0


class HoneypotEngine:
    def __init__(self, cfg: Config, backend: Backend, logger: EventLogger):
        self.cfg, self.backend, self.log = cfg, backend, logger

    # ---------- local deterministic commands (fast, free, perfectly consistent) ----------
    def _local(self, s: Session, cmd: str):
        parts = cmd.split()
        base = parts[0]
        if base in ("exit", "logout"):
            return Result("logout", close=True, source="local")
        if base == "clear":
            return Result("\x1b[H\x1b[2J", source="local")
        if base == "pwd" and len(parts) == 1:
            return Result(s.cwd, source="local")
        if base == "whoami" and len(parts) == 1:
            return Result(s.user, source="local")
        if base == "hostname" and len(parts) == 1:
            return Result(s.hostname, source="local")
        if base == "cd" and len(parts) <= 2:
            target = s.resolve(parts[1] if len(parts) == 2 else "~")
            if target in s.dirs:
                s.cwd = target
                return Result("", source="local")
            return Result(f"bash: cd: {parts[1]}: No such file or directory", source="local")
        if base == "mkdir":
            names = [p for p in parts[1:] if not p.startswith("-")]
            err = []
            for n in names:
                path = s.resolve(n)
                parent = path.rsplit("/", 1)[0] or "/"
                if path in s.dirs and "-p" not in parts:
                    err.append(f"mkdir: cannot create directory '{n}': File exists")
                elif parent not in s.dirs and "-p" not in parts:
                    err.append(f"mkdir: cannot create directory '{n}': No such file or directory")
                else:
                    cur = ""
                    for seg in [x for x in path.split("/") if x]:
                        cur += "/" + seg
                        s.dirs.add(cur)
            return Result("\n".join(err), source="local")
        return None

    def _messages(self, s: Session, cmd: str):
        msgs = []
        for cwd, c, out in s.history:
            msgs.append({"role": "user", "content": f"[{s.user}@{s.hostname} {cwd}] {c}"})
            msgs.append({"role": "assistant", "content": out if out else "<empty>"})
        msgs.append({"role": "user", "content": f"[{s.user}@{s.hostname} {s.cwd}] {cmd}"})
        return msgs

    async def handle(self, s: Session, raw: str) -> Result:
        t0 = time.perf_counter()
        cmd = raw.strip()
        if not cmd:
            return Result("", source="local")
        s.n_cmds += 1
        flags = []
        cwd_before = s.cwd

        if check_input(cmd):
            flags.append("prompt_injection_attempt")
            res = Result(fallback_error(cmd), source="guard")
        else:
            res = self._local(s, cmd)
            if res is None:
                key = cmd if (cmd.split()[0] in IDEMPOTENT or cmd.startswith(("cat /etc/", "cat /proc/"))) else None
                if key and key in s.cache:
                    res = Result(s.cache[key], source="cache")
                else:
                    try:
                        raw_out = await self.backend.complete(build_system(self.cfg, s), self._messages(s, cmd), self.cfg.max_tokens)
                        out, f = sanitize_output(raw_out, cmd, self.cfg.max_output_lines)
                        flags += f
                        res = Result(out, source="llm")
                        if key and "leak_blocked" not in f:
                            s.cache[key] = out
                    except LLMError as e:
                        flags.append("llm_error")
                        self.log.write("llm_error", session=s.id, error=str(e)[:200])
                        res = Result(fallback_error(cmd), source="fallback")

        res.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        s.history.append((cwd_before, cmd, res.output))
        self.log.write("command", session=s.id, src_ip=s.src_ip, user=s.user, cwd=cwd_before, cmd=cmd,
                       techniques=tag_techniques(cmd), flags=flags, source=res.source, latency_ms=res.latency_ms,
                       output_len=len(res.output))
        return res
