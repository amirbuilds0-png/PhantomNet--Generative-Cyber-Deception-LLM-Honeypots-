"""SSH front-end (asyncssh). All shell semantics live in engine.py."""
import argparse
import asyncio
import logging
import os
import time

import asyncssh

from .config import Config, load_config
from .engine import HoneypotEngine
from .llm import make_backend
from .logger import EventLogger
from .persona import banner
from .session import Session


class HoneypotSSH(asyncssh.SSHServer):
    def __init__(self, cfg: Config, log: EventLogger):
        self.cfg, self.log, self.attempts, self.peer = cfg, log, 0, ("?", 0)

    def connection_made(self, conn):
        self.peer = conn.get_extra_info("peername") or ("?", 0)
        self.log.write("connection", src_ip=self.peer[0], src_port=self.peer[1])

    def connection_lost(self, exc):
        self.log.write("disconnect", src_ip=self.peer[0], error=str(exc) if exc else None)

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.attempts += 1
        ok = password in self.cfg.weak_passwords or self.attempts >= self.cfg.accept_after_attempts
        self.log.write("auth", src_ip=self.peer[0], user=username, password=password, success=ok, attempt=self.attempts)
        return ok


def make_handler(cfg: Config, engine: HoneypotEngine, log: EventLogger):
    async def handle(process: asyncssh.SSHServerProcess):
        user = process.get_extra_info("username") or "root"
        peer = process.get_extra_info("peername") or ("?", 0)
        s = Session.new(peer[0], peer[1], user, cfg.hostname, cfg.history_window)
        log.write("session_open", session=s.id, src_ip=s.src_ip, user=user, exec=process.command)
        try:
            if process.command is not None:  # ssh host '<cmd>'
                res = await engine.handle(s, process.command)
                if res.output:
                    process.stdout.write(res.output + "\n")
                process.exit(0)
                return
            process.stdout.write(banner(cfg, s))
            while s.n_cmds < cfg.max_commands:
                process.stdout.write(s.prompt())
                try:
                    line = await asyncio.wait_for(process.stdin.readline(), cfg.session_timeout)
                except asyncio.TimeoutError:
                    break
                except (asyncssh.TerminalSizeChanged, asyncssh.BreakReceived, asyncssh.SignalReceived):
                    continue
                if not line:
                    break
                res = await engine.handle(s, line)
                if res.close:
                    break
                if res.output:
                    process.stdout.write(res.output + "\n")
            process.exit(0)
        except (ConnectionError, asyncssh.Error):
            pass
        finally:
            log.write("session_close", session=s.id, commands=s.n_cmds, duration=round(time.time() - s.started, 1))

    return handle


async def start(cfg: Config):
    os.makedirs(os.path.dirname(cfg.host_key) or ".", exist_ok=True)
    if not os.path.exists(cfg.host_key):
        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        key.write_private_key(cfg.host_key)
    log = EventLogger(cfg.log_path)
    engine = HoneypotEngine(cfg, make_backend(cfg), log)
    return await asyncssh.create_server(lambda: HoneypotSSH(cfg, log), cfg.host, cfg.port,
                                        server_host_keys=[cfg.host_key], process_factory=make_handler(cfg, engine, log),
                                        server_version="OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")


def main():
    ap = argparse.ArgumentParser(description="PhantomNet LLM honeypot")
    ap.add_argument("-c", "--config", default="config.yaml")
    args = ap.parse_args()
    cfg = load_config(args.config)
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = loop.run_until_complete(start(cfg))
    logging.info("PhantomNet listening on %s:%s (backend=%s)", cfg.host, cfg.port, cfg.backend)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        pending = asyncio.all_tasks(loop)
        for t in pending:
            t.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


if __name__ == "__main__":
    main()
