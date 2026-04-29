import time
import logging
import threading
import yaml
from monitor import start_monitoring
from baseline import SlidingWindow, RollingBaseline
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from audit import AuditLogger
from notifier import Notifier  # we'll build this in Phase 6

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Load config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

LOG_PATH = config["log"]["nginx_log_path"]

# Initialize all components
window = SlidingWindow(window_size=config["sliding_window"]["window_size"])
baseline = RollingBaseline(
    window_minutes=config["baseline"]["window_minutes"],
    recalc_interval=config["baseline"]["recalc_interval"],
    min_samples=config["baseline"]["min_samples"]
)
detector = AnomalyDetector(config)
blocker = Blocker(config)
audit_logger = AuditLogger(config["log"]["audit_log_path"])
notifier = Notifier(config)  # stub for now
unbanner = Unbanner(blocker, notifier, audit_logger)

baseline_error_rate = 1.0


def baseline_recorder():
    """
    Background thread — records global rate into baseline every second.
    """
    while True:
        rate = window.get_global_rate()
        baseline.record(rate, audit_logger=audit_logger)
        time.sleep(1)


def handle_request(entry):
    """
    Called for every parsed log entry.
    """
    global baseline_error_rate

    ip = entry["source_ip"]
    status = entry["status"]

    # Skip already-banned IPs — no need to recheck
    if blocker.is_banned(ip):
        return

    # Update sliding window
    window.add(ip, status)

    ip_rate = window.get_ip_rate(ip)
    global_rate = window.get_global_rate()
    ip_error_rate = window.get_ip_error_rate(ip)
    mean, stddev = baseline.get_baseline()

    logger.info(
        f"REQUEST | IP: {ip} | "
        f"Path: {entry['path']} | "
        f"Status: {status} | "
        f"IP Rate: {ip_rate}/60s | "
        f"Global Rate: {global_rate}/60s | "
        f"Mean: {mean:.2f} | Stddev: {stddev:.2f}"
    )

    # Check per-IP anomaly
    ip_anomaly = detector.check_ip(
        ip, ip_rate, ip_error_rate,
        mean, stddev, baseline_error_rate
    )

    if ip_anomaly:
        duration = blocker.ban(
            ip=ip,
            condition=ip_anomaly["condition"],
            rate=ip_rate,
            mean=mean
        )

        if duration is not None:
            # Write to audit log
            audit_logger.log_ban(
                ip=ip,
                condition=ip_anomaly["condition"],
                rate=ip_rate,
                mean=mean,
                duration=duration
            )

            # Send Slack alert (Phase 6)
            notifier.send_ban_alert(
                ip=ip,
                condition=ip_anomaly["condition"],
                rate=ip_rate,
                mean=mean,
                duration=duration
            )

    # Check global anomaly — Slack alert only, no IP block
    global_anomaly = detector.check_global(global_rate, mean, stddev)

    if global_anomaly:
        logger.warning(
            f"[GLOBAL ANOMALY] Condition: {global_anomaly['condition']} | "
            f"Rate: {global_rate} | Mean: {mean:.2f}"
        )
        notifier.send_global_alert(
            condition=global_anomaly["condition"],
            rate=global_rate,
            mean=mean
        )


def main():
    logger.info("Detector daemon starting up...")

    # Start baseline recorder thread
    threading.Thread(target=baseline_recorder, daemon=True).start()
    logger.info("Baseline recorder thread started.")

    # Start unbanner thread
    threading.Thread(target=unbanner.run, daemon=True).start()
    logger.info("Unbanner thread started.")

    # Start monitoring — blocks forever
    start_monitoring(LOG_PATH, handle_request)


if __name__ == "__main__":
    main()