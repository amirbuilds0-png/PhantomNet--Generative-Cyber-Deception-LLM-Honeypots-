import posixpath
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

BASE_DIRS = {"/", "/root", "/home", "/etc", "/var", "/var/log", "/var/www", "/tmp", "/usr", "/usr/bin",
             "/usr/local", "/opt", "/bin", "/dev", "/proc", "/srv", "/mnt", "/boot", "/lib"}


@dataclass
class Session:
    id: str
    src_ip: str
    src_port: int
    user: str
    hostname: str
    cwd: str
    history: deque
    dirs: set
    cache: dict = field(default_factory=dict)
    n_cmds: int = 0
    started: float = field(default_factory=time.time)

    @classmethod
    def new(cls, src_ip, src_port, user, hostname, window=12):
        home = "/root" if user == "root" else f"/home/{user}"
        dirs = set(BASE_DIRS) | {home, f"{home}/.ssh"}
        return cls(uuid.uuid4().hex[:12], src_ip, src_port, user, hostname, home, deque(maxlen=window), dirs)

    @property
    def home(self) -> str:
        return "/root" if self.user == "root" else f"/home/{self.user}"

    def resolve(self, path: str) -> str:
        if not path or path == "~":
            return self.home
        if path.startswith("~/"):
            path = self.home + path[1:]
        if not path.startswith("/"):
            path = posixpath.join(self.cwd, path)
        return posixpath.normpath(path)

    def prompt(self) -> str:
        shown = "~" if self.cwd == self.home else self.cwd
        sym = "#" if self.user == "root" else "$"
        return f"{self.user}@{self.hostname}:{shown}{sym} "
