import logging
from monitor import start_monitoring

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

LOG_PATH = "/var/log/nginx/hng-access.log"


def handle_request(entry):
    """
    This is the callback that receives every parsed log entry.
    For now we just print it. Later this will feed into detection logic.
    """
    logger.info(
        f"REQUEST | IP: {entry['source_ip']} | "
        f"Method: {entry['method']} | "
        f"Path: {entry['path']} | "
        f"Status: {entry['status']}"
    )


def main():
    logger.info("Detector daemon starting up...")
    start_monitoring(LOG_PATH, handle_request)


if __name__ == "__main__":
    main()