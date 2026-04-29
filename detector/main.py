import time
import logging
import threading
import yaml
from monitor import start_monitoring
from baseline import SlidingWindow, RollingBaseline
from detector import AnomalyDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Load config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

LOG_PATH = config["log"]["nginx_log_path"]

# Initialize components
window = SlidingWindow(
    window_size=config["sliding_window"]["window_size"]
)
baseline = RollingBaseline(
    window_minutes=config["baseline"]["window_minutes"],
    recalc_interval=config["baseline"]["recalc_interval"],
    min_samples=config["baseline"]["min_samples"]
)
detector = AnomalyDetector(config)

# Track baseline error rate (errors per 60s window)
baseline_error_rate = 1.0


def baseline_recorder():
    """
    Runs in background thread.
    Every second, records current global rate into the rolling baseline.
    """
    while True:
        rate = window.get_global_rate()
        baseline.record(rate)
        time.sleep(1)


def handle_request(entry):
    """
    Called for every parsed log entry.
    Updates sliding window and runs anomaly detection.
    """
    global baseline_error_rate

    ip = entry["source_ip"]
    status = entry["status"]

    # Update sliding window
    window.add(ip, status)

    # Get current rates
    ip_rate = window.get_ip_rate(ip)
    global_rate = window.get_global_rate()
    ip_error_rate = window.get_ip_error_rate(ip)

    # Get current baseline
    mean, stddev = baseline.get_baseline()

    logger.info(
        f"REQUEST | IP: {ip} | "
        f"Path: {entry['path']} | "
        f"Status: {status} | "
        f"IP Rate: {ip_rate}/60s | "
        f"Global Rate: {global_rate}/60s | "
        f"Mean: {mean:.2f} | "
        f"Stddev: {stddev:.2f}"
    )

    # Run per-IP anomaly check
    ip_anomaly = detector.check_ip(
        ip, ip_rate, ip_error_rate,
        mean, stddev, baseline_error_rate
    )

    if ip_anomaly:
        logger.warning(
            f"[ANOMALY DETECTED] Type: IP | "
            f"IP: {ip} | "
            f"Condition: {ip_anomaly['condition']} | "
            f"Rate: {ip_rate} | "
            f"Mean: {mean:.2f}"
        )
        # blocker.py will be wired in here in Phase 5

    # Run global anomaly check
    global_anomaly = detector.check_global(global_rate, mean, stddev)

    if global_anomaly:
        logger.warning(
            f"[ANOMALY DETECTED] Type: GLOBAL | "
            f"Condition: {global_anomaly['condition']} | "
            f"Rate: {global_rate} | "
            f"Mean: {mean:.2f}"
        )
        # notifier.py will be wired in here in Phase 5


def main():
    logger.info("Detector daemon starting up...")

    # Start baseline recorder thread
    recorder_thread = threading.Thread(
        target=baseline_recorder,
        daemon=True
    )
    recorder_thread.start()
    logger.info("Baseline recorder thread started.")

    # Start monitoring — blocks forever
    start_monitoring(LOG_PATH, handle_request)


if __name__ == "__main__":
    main()