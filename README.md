# HNG Anomaly Detection Daemon

A real-time traffic anomaly detection engine for a Nextcloud Docker deployment,
built for the HNG DevSecOps track. The daemon tails Nginx access logs, computes
a self-calibrating baseline, detects per-IP and global traffic anomalies using
z-score statistics, and automatically bans offending IPs via `iptables`. All
events are logged to a structured audit file and reported to Slack.

---

## Live Links

- **Server IP:** _(fill in)_
- **Dashboard URL:** _(fill in)_
- **GitHub Repo:** _(fill in)_

---

## Language Choice

Python was chosen over Go for the following reasons:

- **Standard library depth.** `collections.deque`, `statistics`, `subprocess`,
  `threading`, and `logging` are all built in — no external packages needed for
  the core detection logic.
- **Rapid iteration.** The detection algorithm required multiple refinement
  cycles (baseline tuning, error-surge logic, hourly slots). Python's
  interactive feedback loop made that significantly faster than a compiled
  language.
- **Ecosystem fit.** Flask (dashboard), requests (Slack webhook), PyYAML
  (config), and psutil (system metrics) are all mature, well-documented Python
  packages with minimal setup overhead.
- **Readability.** The z-score formula, deque eviction, and baseline logic are
  easier to audit and explain in Python, which matters for a security-critical
  component.

Go would offer better raw performance, but the daemon is I/O-bound (tailing a
log file) rather than CPU-bound, so Python's performance is entirely adequate.

---

## Architecture

```
Nginx (reverse proxy)
  │
  │  writes JSON access logs
  ▼
/var/log/nginx/hng-access.log   (shared Docker volume)
  │
  │  tailed by
  ▼
monitor.py  ──────────────────────────────────────────────────┐
  │  parses JSON lines, calls handle_request()                │
  ▼                                                           │
main.py (handle_request)                                      │
  ├── SlidingWindow (baseline.py)   tracks last-60s rates     │
  ├── RollingBaseline (baseline.py) computes mean & stddev    │
  ├── AnomalyDetector (detector.py) z-score + multiplier      │
  ├── Blocker (blocker.py)          iptables DROP rules        │
  ├── AuditLogger (audit.py)        structured file log        │
  └── Notifier (notifier.py)        Slack webhooks             │
                                                               │
  background threads:                                          │
  ├── baseline_recorder  samples global rate every 1 second ──┘
  ├── Unbanner           checks for expired bans every 30s
  └── Dashboard          Flask HTTP server on port 8080
```

See [`detector/docs/architecture.png`](detector/docs/architecture.png) for the
visual diagram.

---

## How the Sliding Window Works

Think of the sliding window as a receipt tape. Every time a request comes in,
you write the current time on the right end of the tape. Every time you want to
know the current rate, you tear off anything on the left that is more than 60
seconds old.

Internally this is a `collections.deque` — a double-ended queue that is very
fast at adding to the right and removing from the left.

**Example — one IP's window at t = 1000s:**

```
Tape:  [930, 940, 950, 960, 980, 995, 1000]
         ^-- 70s ago, stale      ^-- fresh
```

The eviction loop runs:
- `1000 - 930 = 70 > 60` → pop from left
- `1000 - 940 = 60` → stop (not strictly greater)

Result: `[940, 950, 960, 980, 995, 1000]` — 6 requests in the last 60 seconds.

**Two windows are maintained in parallel:**

| Window | Purpose |
|---|---|
| `per_ip[source_ip]` | One deque per IP address — used to detect per-IP spikes |
| `global_window` | One deque for all traffic combined — used to detect fleet-wide spikes |

A third family of deques, `per_ip_errors`, tracks 4xx/5xx responses per IP for
error-surge detection.

Because `popleft()` on a deque is O(1), eviction is fast no matter how many
stale entries need to be removed in one pass.

---

## How the Baseline Works

The baseline answers the question: "given recent traffic history, what is the
normal request rate, and how much does it normally vary?"

**Rolling 30-minute window:**
Every second, the baseline recorder thread reads the current global rate (number
of requests in the last 60 s) and appends it to a rolling history deque. The
deque automatically drops entries older than 30 minutes (1800 seconds), so it
always holds at most ~1800 data points — one per second for the last half-hour.

**Recalculation every 60 seconds:**
Mean and stddev are recomputed from the rolling history once per minute. There
is no need to recompute on every request — the statistics barely change from one
second to the next, and doing so under heavy load would waste CPU needlessly.

**Per-hour slots:**
Traffic patterns are strongly time-of-day dependent — a server might normally
see 200 req/s at 2 PM but only 5 req/s at 3 AM. To avoid mixing these, every
data point is also stored in `hourly_slots[current_hour]` (keyed 0–23). When
recalculating, the detector prefers the current hour's slot if it has at least
30 samples. Otherwise it falls back to the full 30-minute window.

**Floor values of 1.0:**
The effective mean and stddev are never allowed to fall below 1.0. A zero mean
would make the z-score meaningless for any non-zero traffic; a zero stddev would
break the z-score formula. The floor of 1.0 keeps the detector functional during
low-traffic or startup periods.

**The baseline is never hardcoded.**
Every value of `effective_mean` and `effective_stddev` is computed from real
observed traffic. If traffic patterns change — due to a new feature launch, a
change in user base, or a shift in load — the baseline adapts automatically
within the next 60-second recalculation cycle.

---

## How Detection Works

### Z-score threshold (primary condition)

For each request the detector computes:

```
z = (current_rate - mean) / stddev
```

If `z > 3.0` (the default `z_score_threshold`), the IP is flagged. A z-score
of 3.0 means the rate is three standard deviations above normal — statistically,
only ~0.13% of legitimate traffic ever reaches this level.

### 5× rate multiplier (safety-net condition)

Even if the z-score is below 3.0 (which can happen when stddev is temporarily
inflated), if the IP's rate exceeds `5 × mean` the IP is still flagged. This
catches extreme spikes that the z-score alone might miss during noisy traffic
periods.

### Error surge tightening

If an IP's 4xx/5xx error rate is 3× or more than the baseline error rate, its
z-score threshold is tightened from 3.0 to 2.0 for all future checks. An IP
that is already probing with bad requests gets a lower tolerance.

### Per-IP vs global anomaly response

| Event | Response |
|---|---|
| **Per-IP anomaly** | iptables DROP rule added + Slack ban alert + audit log entry |
| **Global anomaly** | Slack alert only — no IP ban |

A global spike means many IPs are each sending normal amounts of traffic
simultaneously (e.g., a viral link or scheduled job). Banning IPs in that
scenario would harm legitimate users while doing nothing to reduce the load.

---

## Blocking and Unban Schedule

When a per-IP anomaly is detected, `blocker.py` inserts an `iptables` rule:

```bash
iptables -I INPUT -s <IP> -j DROP
```

`-I` inserts at the top of the INPUT chain, giving it highest priority over
any other rules.

Bans are temporary and follow a backoff schedule based on how many times the
same IP has been banned before:

| Ban count | Duration |
|---|---|
| 1st ban | 10 minutes (600 s) |
| 2nd ban | 30 minutes (1 800 s) |
| 3rd ban | 2 hours (7 200 s) |
| 4th ban+ | Permanent |

The unbanner thread checks for expired bans every 30 seconds. When a ban
expires, the iptables rule is removed with:

```bash
iptables -D INPUT -s <IP> -j DROP
```

A Slack unban notification is sent and an audit log entry is written. Permanent
bans (`duration = -1`) are never checked for expiry and require manual removal.

---

## Slack Alerts

Three types of alerts are sent to the configured `SLACK_WEBHOOK_URL`:

| Alert | Trigger | Contains |
|---|---|---|
| **IP BANNED** | Per-IP anomaly detected | IP, condition, current rate, baseline mean, ban duration, timestamp |
| **IP UNBANNED** | Ban duration expired | IP, total ban count, previous duration, timestamp |
| **GLOBAL TRAFFIC SPIKE** | Global anomaly detected | Condition, global rate, baseline mean, "alert only" note, timestamp |

---

## Setup Instructions

These steps take you from a fresh Ubuntu VPS to a fully running stack.

### 1. Install Docker

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Clone the repository

```bash
git clone <your-repo-url>
cd anomaly-detection-daemon
```

### 3. Create the `.env` file

```bash
cat > .env <<'EOF'
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
EOF
```

Replace the URL with your actual Slack incoming webhook URL.

### 4. Build and start the stack

```bash
docker compose up --build -d
```

### 5. Verify all containers are running

```bash
docker compose ps
```

You should see `nextcloud`, `nginx`, and `detector` all with status `running`.

```bash
# Check detector logs
docker logs detector --tail 50 -f

# Check the live dashboard
curl http://localhost:8080
```

The dashboard is also accessible at `http://<your-server-ip>:8080` or via the
`monitor.yomiladun.com` subdomain if DNS is configured.

---

## Required Screenshots

All screenshots are saved in the `screenshots/` folder at the project root.

| File | What it shows |
|---|---|
| `screenshots/Tool-running.png` | Detector daemon running and processing live log lines |
| `screenshots/Ban-slack.png` | Slack ban notification after an IP anomaly |
| `screenshots/Unban-slack.png` | Slack unban notification after a ban expires |
| `screenshots/Global-alert-slack.png` | Slack global traffic spike notification |
| `screenshots/Iptables-banned.png` | `sudo iptables -L -n` output showing a blocked IP |
| `screenshots/Audit-log.png` | Structured audit log with ban, unban, and baseline recalculation entries |
| `screenshots/Baseline-graph.png` | Baseline over time showing at least two hourly slots with visibly different effective_mean values |

---

## Repository Structure

```
anomaly-detection-daemon/
├── detector/
│   ├── main.py           # Entry point — wires all components together
│   ├── monitor.py        # Tails Nginx log file, parses JSON lines
│   ├── baseline.py       # SlidingWindow + RollingBaseline
│   ├── detector.py       # AnomalyDetector — z-score and rate checks
│   ├── blocker.py        # Manages iptables DROP rules and ban state
│   ├── unbanner.py       # Background thread — lifts expired bans
│   ├── notifier.py       # Sends Slack alerts
│   ├── dashboard.py      # Flask live metrics dashboard
│   ├── audit.py          # Writes structured audit log entries
│   ├── config.yaml       # All tunable thresholds and paths
│   ├── requirements.txt  # Python dependencies
│   └── Dockerfile
├── nginx/
│   └── nginx.conf        # JSON access log format, reverse proxy to Nextcloud
├── docs/
│   └── architecture.png  # System architecture diagram
├── screenshots/          # Required evidence screenshots
├── docker-compose.yml    # Nextcloud + Nginx + Detector stack
├── .env                  # SLACK_WEBHOOK_URL (not committed)
├── .gitignore
└── README.md
```
