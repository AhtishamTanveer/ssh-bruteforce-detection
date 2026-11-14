import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
WINDOW = timedelta(minutes=5)
THRESHOLD = 5  # failures inside one window that count as brute force
YEAR = 2026    # auth.log lines have no year

PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)

# 1. Parse: collect failure timestamps per IP
failures = defaultdict(list)
for line in open(LOG_FILE, encoding="utf-8", errors="ignore"):
    m = PATTERN.search(line)
    if m:
        t = datetime.strptime(f"{YEAR} {m['ts']}", "%Y %b %d %H:%M:%S")
        failures[m["ip"]].append(t)

# 2. Sliding window: best count of failures within any 5-minute span
results = []
for ip, times in failures.items():
    times.sort()
    best, best_start, best_end = 0, None, None
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > WINDOW:
            left += 1
        count = right - left + 1
        if count > best:
            best, best_start, best_end = count, times[left], times[right]
    results.append((ip, best, len(times), best_start, best_end))

# 3. Report
results.sort(key=lambda r: r[1], reverse=True)
flagged = [r for r in results if r[1] >= THRESHOLD]

if not flagged:
    print("No brute-force activity detected.")
else:
    ip, best, total, start, end = flagged[0]
    print(f"Suspicious IP: {ip}, Attempts: {best}, "
          f"Time Range: {start:%H:%M}-{end:%H:%M}")
    print(f"Total failed attempts from this IP: {total}")
    print()
    print("All IPs with failed logins:")
    for ip, best, total, start, end in results:
        status = "SUSPICIOUS" if best >= THRESHOLD else "ok"
        print(f"  {ip:<16} max in 5 min: {best:<3} total: {total:<3} [{status}]")