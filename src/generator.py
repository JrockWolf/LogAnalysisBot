from pathlib import Path
import random
import time
from datetime import datetime, timedelta

def _ts(t: datetime):
    return t.strftime("%b %d %H:%M:%S")


def generate_samples(out: Path, seed: int = None):
    """Generate a single text log with multiple events."""
    if seed is not None:
        random.seed(seed)
    now = datetime.utcnow()
    lines = []
    # multiple failed SSH attempts from same IP
    ip = f"192.0.2.{random.randint(2,250)}"
    user = random.choice(["root", "admin", "bob", "alice"])
    for i in range(5):
        t = now - timedelta(minutes=random.randint(0, 50))
        port = random.randint(1024, 65535)
        lines.append(
            f"{_ts(t)} sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {port} ssh2"
        )

    # a privilege escalation attempt
    t = now - timedelta(minutes=random.randint(0, 120))
    lines.append(
        f"{_ts(t)} sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    )

    # unauthorized file access (audit-like line)
    t = now - timedelta(hours=2)
    lines.append(
        f"{_ts(t)} kernel: audit: type=AVC msg=audit(\"{int(time.time())}\"): name=/etc/shadow op=open uid={random.randint(1000,2000)} gid=0"
    )

    # some benign activity
    for i in range(3):
        t = now - timedelta(minutes=random.randint(0, 300))
        lines.append(
            f"{_ts(t)} CRON[{random.randint(100,900)}]: (root) CMD (run-parts /etc/cron.hourly)"
        )

    out.write_text("\n".join(lines), encoding="utf-8")
