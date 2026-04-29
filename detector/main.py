import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def main():
    logger.info("Detector daemon starting up...")
    logger.info("Watching for Nginx logs at /var/log/nginx/hng-access.log")
    
    while True:
        logger.info("Daemon is running and waiting for logs...")
        time.sleep(10)

if __name__ == "__main__":
    main()