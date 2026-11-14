import random
from datetime import datetime, timedelta

random.seed(42)
HOST = "greenfield-srv"
start = datetime(2026, 11, 13, 10, 0, 0)
names = ["admin", "oracle", "test", "user", "postgres", "ftpuser"]
events = []

# Attacker: 15 failures from one IP, 20 seconds apart (10:00:00 to 10:04:40)
for i in range(15):
    t = start + timedelta(seconds=i * 20)
    events.append((t, f"Failed password for invalid user {random.choice(names)} "
                      f"from 192.168.1.50 port {52000 + i} ssh2"))

# Noise: a few slow failures from other IPs
noise = {"10.0.0.23": (3, 47), "203.0.113.7": (2, 65), "198.51.100.9": (4, 31)}
for ip, (count, gap) in noise.items():
    for i in range(count):
        t = start + timedelta(minutes=10 + i * gap)
        events.append((t, f"Failed password for invalid user {random.choice(names)} "
                          f"from {ip} port {41000 + random.randint(0, 999)} ssh2"))

# One normal login
events.append((start + timedelta(minutes=30),
               "Accepted password for ahtisham from 192.168.1.20 port 50111 ssh2"))

events.sort(key=lambda e: e[0])
for n, (t, msg) in enumerate(events):
    print(f"{t:%b %d %H:%M:%S} {HOST} sshd[{1200 + n}]: {msg}")