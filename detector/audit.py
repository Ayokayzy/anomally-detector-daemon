import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Writes structured log entries for every ban, unban,
    and baseline recalculation.
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, log_path):
        self.log_path = log_path
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def _write(self, line):
        """
        Append a line to the audit log file.
        """
        try:
            with open(self.log_path, "a") as f:
                f.write(line + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def log_ban(self, ip, condition, rate, mean, duration):
        """
        Log a ban event.
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        duration_str = f"{duration}s" if duration != -1 else "permanent"
        line = (
            f"[{timestamp}] BAN {ip} | "
            f"condition={condition} | "
            f"rate={rate} | "
            f"baseline={mean:.2f} | "
            f"duration={duration_str}"
        )
        self._write(line)
        logger.info(f"AUDIT: {line}")

    def log_unban(self, ip, ban_count, duration):
        """
        Log an unban event.
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        duration_str = f"{duration}s" if duration != -1 else "permanent"
        line = (
            f"[{timestamp}] UNBAN {ip} | "
            f"ban_count={ban_count} | "
            f"previous_duration={duration_str}"
        )
        self._write(line)
        logger.info(f"AUDIT: {line}")

    def log_baseline_recalc(self, source, samples, mean, stddev):
        """
        Log a baseline recalculation event.
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        line = (
            f"[{timestamp}] BASELINE_RECALC | "
            f"source={source} | "
            f"samples={samples} | "
            f"mean={mean:.2f} | "
            f"stddev={stddev:.2f}"
        )
        self._write(line)
        logger.info(f"AUDIT: {line}")