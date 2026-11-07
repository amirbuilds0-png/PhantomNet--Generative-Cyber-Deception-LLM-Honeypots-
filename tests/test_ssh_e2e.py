import asyncio
import asyncssh

from phantomnet.config import Config
from phantomnet.server import start


def test_ssh_end_to_end(tmp_path):
    async def go():
        cfg = Config(host="127.0.0.1", port=22922, host_key=str(tmp_path / "k"), log_path=str(tmp_path / "l.jsonl"))
        srv = await start(cfg)
        try:
            async with asyncssh.connect("127.0.0.1", 22922, username="root", password="123456", known_hosts=None) as c:
                r = await c.run("uname -a")
                assert "Linux srv-db-02" in r.stdout
                p = await c.create_process(term_type="xterm")
                p.stdin.write("mkdir /tmp/x\ncd /tmp/x\npwd\nexit\n")
                out = await asyncio.wait_for(p.stdout.read(), 10)
                assert "/tmp/x" in out
        finally:
            srv.close()
            await srv.wait_closed()
        log = (tmp_path / "l.jsonl").read_text()
        assert '"event": "auth"' in log and '"event": "command"' in log
    asyncio.run(go())
