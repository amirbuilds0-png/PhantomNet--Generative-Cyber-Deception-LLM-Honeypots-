import os
from dataclasses import dataclass, field, fields
import yaml


@dataclass
class Config:
    host: str = "0.0.0.0"
    port: int = 2222
    host_key: str = "data/ssh_host_key"
    log_path: str = "logs/phantomnet.jsonl"
    hostname: str = "srv-db-02"
    os_banner: str = "Ubuntu 22.04.3 LTS"
    kernel: str = "5.15.0-91-generic"
    accept_after_attempts: int = 2
    weak_passwords: list = field(default_factory=lambda: ["123456", "password", "admin", "root", "toor", "ubuntu"])
    backend: str = "mock"
    model: str = "claude-haiku-5-5"
    base_url: str = "http://localhost:11434/v1"
    max_tokens: int = 400
    history_window: int = 12
    llm_timeout: float = 15.0
    max_output_lines: int = 60
    session_timeout: int = 300
    max_commands: int = 200


def load_config(path: str | None = None) -> Config:
    cfg = Config()
    if path and os.path.exists(path):
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    for f in fields(cfg):
        env = os.environ.get(f"PHANTOMNET_{f.name.upper()}")
        if env is not None:
            cur = getattr(cfg, f.name)
            if isinstance(cur, bool):
                setattr(cfg, f.name, env.lower() in ("1", "true", "yes"))
            elif isinstance(cur, int):
                setattr(cfg, f.name, int(env))
            elif isinstance(cur, float):
                setattr(cfg, f.name, float(env))
            elif isinstance(cur, str):
                setattr(cfg, f.name, env)
    return cfg
