import time
import logging
import threading
from monitor import start_monitoring
from baseline import SlidingWindow, RollingBaseline

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

LOG_PATH = "/var/log/nginx/hng-access.log"

# Initialize sliding window and baseline
window = SlidingWindow(window_size=60)
baseline = RollingBaseline(window_minutes=30, recalc_interval=60)


def baseline_recorder():
    """
    Runs in a separate thread.
    Every second, records the current global request rate
    into the rolling baseline.
    """
    while True:
        rate = window.get_global_rate()
        baseline.record(rate)
        time.sleep(1)


def handle_request(entry):
    """
    Called for every parsed log entry.
    Updates the sliding window with the new request.
    """
    ip = entry["source_ip"]
    status = entry["status"]

    # Update sliding window
    window.add(ip, status)

    # Get current rates
    ip_rate = window.get_ip_rate(ip)
    global_rate = window.get_global_rate()

    logger.info(
        f"REQUEST | IP: {ip} | "
        f"Path: {entry['path']} | "
        f"Status: {status} | "
        f"IP Rate: {ip_rate}/60s | "
        f"Global Rate: {global_rate}/60s"
    )


def main():
    logger.info("Detector daemon starting up...")

    # Start baseline recorder in background thread
    recorder_thread = threading.Thread(
        target=baseline_recorder,
        daemon=True
    )
    recorder_thread.start()
    logger.info("Baseline recorder thread started.")

    # Start monitoring — this blocks and runs forever
    start_monitoring(LOG_PATH, handle_request)


if __name__ == "__main__":
    main()