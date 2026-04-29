import time
import logging
import threading
import psutil
from flask import Flask, jsonify, render_template_string
from datetime import datetime

logger = logging.getLogger(__name__)

# HTML template for the dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HNG Anomaly Detector — Live Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff41;
            padding: 20px;
        }
        h1 {
            text-align: center;
            font-size: 1.8em;
            margin-bottom: 5px;
            color: #00ff41;
            text-shadow: 0 0 10px #00ff41;
        }
        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 20px;
            font-size: 0.85em;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .card {
            background: #111;
            border: 1px solid #00ff4133;
            border-radius: 8px;
            padding: 15px;
        }
        .card h2 {
            font-size: 0.8em;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 10px;
        }
        .metric {
            font-size: 2em;
            font-weight: bold;
            color: #00ff41;
        }
        .metric.danger { color: #ff4141; }
        .metric.warning { color: #ffaa00; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }
        th {
            color: #888;
            text-align: left;
            padding: 5px 8px;
            border-bottom: 1px solid #222;
            font-size: 0.75em;
            text-transform: uppercase;
        }
        td {
            padding: 6px 8px;
            border-bottom: 1px solid #1a1a1a;
        }
        td.banned { color: #ff4141; }
        .uptime { color: #888; font-size: 0.8em; margin-top: 5px; }
        .refresh-bar {
            text-align: center;
            color: #444;
            font-size: 0.75em;
            margin-top: 15px;
        }
        .dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #00ff41;
            margin-right: 6px;
            animation: pulse 1s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
    </style>
</head>
<body>
    <h1><span class="dot"></span>HNG Anomaly Detector</h1>
    <p class="subtitle">Live Traffic Monitor — Nextcloud Security Layer</p>

    <div class="grid">
        <div class="card">
            <h2>Global Req/s (last 60s)</h2>
            <div class="metric" id="global-rate">--</div>
        </div>
        <div class="card">
            <h2>Banned IPs</h2>
            <div class="metric danger" id="banned-count">--</div>
        </div>
        <div class="card">
            <h2>Baseline Mean</h2>
            <div class="metric" id="mean">--</div>
        </div>
        <div class="card">
            <h2>Baseline Stddev</h2>
            <div class="metric" id="stddev">--</div>
        </div>
        <div class="card">
            <h2>CPU Usage</h2>
            <div class="metric" id="cpu">--</div>
        </div>
        <div class="card">
            <h2>Memory Usage</h2>
            <div class="metric" id="memory">--</div>
        </div>
    </div>

    <div class="card" style="margin-bottom: 15px;">
        <h2>Banned IPs</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Condition</th>
                    <th>Rate</th>
                    <th>Duration</th>
                    <th>Banned At</th>
                    <th>Ban #</th>
                </tr>
            </thead>
            <tbody id="banned-table">
                <tr><td colspan="6" style="color:#444">No banned IPs</td></tr>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Top 10 Source IPs (last 60s)</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Requests</th>
                </tr>
            </thead>
            <tbody id="top-ips-table">
                <tr><td colspan="2" style="color:#444">No traffic yet</td></tr>
            </tbody>
        </table>
    </div>

    <div class="refresh-bar">
        Auto-refreshing every 3 seconds |
        Uptime: <span id="uptime">--</span> |
        Last update: <span id="last-update">--</span>
    </div>

<script>
    async function fetchMetrics() {
        try {
            const res = await fetch('/api/metrics');
            const data = await res.json();

            document.getElementById('global-rate').textContent = data.global_rate;
            document.getElementById('banned-count').textContent = data.banned_count;
            document.getElementById('mean').textContent = data.mean.toFixed(2);
            document.getElementById('stddev').textContent = data.stddev.toFixed(2);
            document.getElementById('cpu').textContent = data.cpu + '%';
            document.getElementById('memory').textContent = data.memory + '%';
            document.getElementById('uptime').textContent = data.uptime;
            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();

            // Update banned IPs table
            const bannedTbody = document.getElementById('banned-table');
            if (data.banned_ips.length === 0) {
                bannedTbody.innerHTML = '<tr><td colspan="6" style="color:#444">No banned IPs</td></tr>';
            } else {
                bannedTbody.innerHTML = data.banned_ips.map(b => `
                    <tr>
                        <td class="banned">${b.ip}</td>
                        <td>${b.condition}</td>
                        <td>${b.rate}</td>
                        <td>${b.duration === -1 ? 'PERMANENT' : b.duration + 's'}</td>
                        <td>${b.banned_at}</td>
                        <td>${b.ban_count}</td>
                    </tr>
                `).join('');
            }

            // Update top IPs table
            const topTbody = document.getElementById('top-ips-table');
            if (data.top_ips.length === 0) {
                topTbody.innerHTML = '<tr><td colspan="2" style="color:#444">No traffic yet</td></tr>';
            } else {
                topTbody.innerHTML = data.top_ips.map(([ip, count]) => `
                    <tr>
                        <td>${ip || '(empty)'}</td>
                        <td>${count}</td>
                    </tr>
                `).join('');
            }
        } catch (err) {
            console.error('Failed to fetch metrics:', err);
        }
    }

    // Fetch immediately then every 3 seconds
    fetchMetrics();
    setInterval(fetchMetrics, 3000);
</script>
</body>
</html>
"""


class Dashboard:
    """
    Flask-based live metrics dashboard.
    Serves at configured port, auto-refreshes every 3 seconds.
    """

    def __init__(self, config, window, baseline, blocker):
        self.config = config
        self.window = window
        self.baseline = baseline
        self.blocker = blocker
        self.port = config["dashboard"]["port"]
        self.start_time = time.time()

        self.app = Flask(__name__)
        self._register_routes()

    def _uptime_str(self):
        """
        Return human-readable uptime string.
        """
        seconds = int(time.time() - self.start_time)
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs}s"

    def _register_routes(self):

        @self.app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @self.app.route("/api/metrics")
        def metrics():
            mean, stddev = self.baseline.get_baseline()
            banned = self.blocker.get_banned_ips()
            top_ips = self.window.get_top_ips(10)

            banned_list = []
            for ip, info in banned.items():
                banned_list.append({
                    "ip": ip,
                    "condition": info.get("condition", ""),
                    "rate": info.get("rate", 0),
                    "duration": info.get("duration", 0),
                    "ban_count": info.get("ban_count", 0),
                    "banned_at": datetime.utcfromtimestamp(
                        info.get("banned_at", 0)
                    ).strftime("%H:%M:%S UTC"),
                })

            return jsonify({
                "global_rate": self.window.get_global_rate(),
                "banned_count": len(banned),
                "banned_ips": banned_list,
                "top_ips": top_ips,
                "mean": mean,
                "stddev": stddev,
                "cpu": psutil.cpu_percent(interval=None),
                "memory": psutil.virtual_memory().percent,
                "uptime": self._uptime_str(),
            })

    def run(self):
        """
        Start the Flask dashboard server.
        Runs in a background thread.
        """
        logger.info(f"Dashboard starting on port {self.port}")
        self.app.run(
            host="0.0.0.0",
            port=self.port,
            debug=False,
            use_reloader=False
        )