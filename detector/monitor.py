import json
import time
import os
import logging

logger = logging.getLogger(__name__)


def follow(log_path):
    """
    Continuously tail a log file, yielding new lines as they appear.
    Works like 'tail -f' in the terminal.
    """
    # Wait until the log file exists before starting
    while not os.path.exists(log_path):
        logger.info(f"Waiting for log file to appear at {log_path}...")
        time.sleep(2)

    logger.info(f"Log file found. Starting to tail: {log_path}")

    with open(log_path, "r") as f:
        # Move to the end of the file so we only read NEW lines
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                # No new line yet, wait a moment and try again
                time.sleep(0.1)
                continue

            yield line.strip()


def parse_line(line):
    """
    Parse a single JSON log line into a structured dictionary.
    Returns None if the line is not valid JSON.
    """
    try:
        entry = json.loads(line)

        return {
            "source_ip": entry.get("source_ip", ""),
            "timestamp": entry.get("timestamp", ""),
            "method": entry.get("method", ""),
            "path": entry.get("path", ""),
            "status": int(entry.get("status", 0)),
            "response_size": int(entry.get("response_size", 0)),
        }

    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Failed to parse log line: {line} | Error: {e}")
        return None


def start_monitoring(log_path, callback):
    """
    Main monitoring loop. Tails the log file, parses each line,
    and passes the result to the callback function.
    """
    logger.info("Monitor started.")

    for raw_line in follow(log_path):
        parsed = parse_line(raw_line)

        if parsed:
            callback(parsed)