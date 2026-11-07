"""LLM backends: Anthropic, any OpenAI-compatible API (OpenAI, Ollama, vLLM...), and an offline Mock for tests."""
import os
import re
import httpx

from .config import Config


class LLMError(Exception):
    pass


class Backend:
    async def complete(self, system: str, messages: list, max_tokens: int) -> str:
        raise NotImplementedError


class AnthropicBackend(Backend):
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.key = os.environ.get("ANTHROPIC_API_KEY")
        if not self.key:
            raise LLMError("ANTHROPIC_API_KEY not set")

    async def complete(self, system, messages, max_tokens):
        try:
            async with httpx.AsyncClient(timeout=self.cfg.llm_timeout) as c:
                r = await c.post("https://api.anthropic.com/v1/messages",
                                 headers={"x-api-key": self.key, "anthropic-version": "2023-06-01"},
                                 json={"model": self.cfg.model, "max_tokens": max_tokens, "temperature": 0.3,
                                       "system": system, "messages": messages})
            r.raise_for_status()
            return "".join(b.get("text", "") for b in r.json()["content"])
        except Exception as e:  # network, HTTP, parse
            raise LLMError(str(e)) from e


class OpenAICompatBackend(Backend):
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.key = os.environ.get("OPENAI_API_KEY", "ollama")

    async def complete(self, system, messages, max_tokens):
        try:
            async with httpx.AsyncClient(timeout=self.cfg.llm_timeout) as c:
                r = await c.post(f"{self.cfg.base_url.rstrip('/')}/chat/completions",
                                 headers={"Authorization": f"Bearer {self.key}"},
                                 json={"model": self.cfg.model, "max_tokens": max_tokens, "temperature": 0.3,
                                       "messages": [{"role": "system", "content": system}, *messages]})
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            raise LLMError(str(e)) from e


class MockBackend(Backend):
    """Deterministic offline emulator used for unit tests and cost-free demos."""
    FILES = {
        "/root": [".bash_history", ".bashrc", ".ssh", "backup.sh", "notes.txt"],
        "/etc": ["passwd", "shadow", "hosts", "ssh", "nginx", "crontab"],
        "/var/www": ["html"],
        "/tmp": [],
    }
    PASSWD = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
              "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:112:118:MySQL Server:/nonexistent:/bin/false\n"
              "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash")

    async def complete(self, system, messages, max_tokens):
        last = messages[-1]["content"]
        m = re.match(r"\[(\S+)@(\S+) (\S+)\] (.*)$", last, re.S)
        user, host, cwd, cmd = m.groups() if m else ("root", "srv", "/root", last)
        cmd = cmd.strip()
        parts = cmd.split()
        base = parts[0] if parts else ""
        if base == "uname":
            return f"Linux {host} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
        if base == "id":
            return "uid=0(root) gid=0(root) groups=0(root)" if user == "root" else f"uid=1001({user}) gid=1001({user}) groups=1001({user})"
        if base == "ls":
            names = self.FILES.get(cwd, [])
            return "\n".join(names) if names else "<empty>"
        if cmd.startswith("cat /etc/passwd"):
            return self.PASSWD
        if base == "uptime":
            return " 02:41:07 up 41 days,  6:12,  1 user,  load average: 0.08, 0.03, 0.01"
        if base == "ps":
            return ("USER       PID %CPU %MEM COMMAND\nroot         1  0.0  0.1 /sbin/init\nroot       612  0.0  0.1 /usr/sbin/sshd -D\n"
                    "mysql      845  0.4  4.2 /usr/sbin/mysqld\nwww-data  1021  0.0  0.3 nginx: worker process")
        if base in ("ifconfig", "ip"):
            return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255"
        if base in ("wget", "curl"):
            return "curl: (28) Connection timed out after 10001 milliseconds" if base == "curl" else "--02:41:09--  connecting...\nFailed: Connection timed out."
        if base in ("mkdir", "touch", "chmod", "rm", "export", "cp", "mv", "echo") and ">" not in cmd:
            return "<empty>" if base != "echo" else " ".join(parts[1:])
        if base in ("df",):
            return "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        79G   25G   51G  34% /"
        if base in ("free",):
            return "              total        used        free\nMem:        8167420     1923344     4120232"
        return f"bash: {base}: command not found"


def make_backend(cfg: Config) -> Backend:
    return {"anthropic": AnthropicBackend, "openai": OpenAICompatBackend, "mock": lambda c: MockBackend()}[cfg.backend](cfg)
