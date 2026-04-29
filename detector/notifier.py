import os
import requests
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class Notifier:
    """
    Sends Slack alerts for ban, unban, and global anomaly events.
    Webhook URL is loaded from config.yaml.
    All alerts include: condition, current rate, baseline, timestamp,
    and ban duration where applicable.
    """

    def __init__(self, config):
        self.webhook_url = os.environ.get(
            "SLACK_WEBHOOK_URL",
            config["slack"]["webhook_url"]
        )

    def _send(self, message):
        """
        POST a message to the Slack webhook.
        """
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured — skipping alert.")
            return

        try:
            response = requests.post(
                self.webhook_url,
                json={"text": message},
                timeout=5
            )
            if response.status_code != 200:
                logger.error(
                    f"Slack alert failed: {response.status_code} | {response.text}"
                )
            else:
                logger.info("Slack alert sent successfully.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Slack request error: {e}")

    def send_ban_alert(self, ip, condition, rate, mean, duration):
        """
        Send a Slack alert when an IP is banned.
        """
        duration_str = f"{duration} seconds" if duration != -1 else "PERMANENT"
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        message = (
            f":rotating_light: *IP BANNED*\n"
            f">*IP:* `{ip}`\n"
            f">*Condition:* {condition}\n"
            f">*Current Rate:* {rate} req/60s\n"
            f">*Baseline Mean:* {mean:.2f} req/s\n"
            f">*Ban Duration:* {duration_str}\n"
            f">*Timestamp:* {timestamp}"
        )
        self._send(message)

    def send_unban_alert(self, ip, ban_count, duration):
        """
        Send a Slack alert when an IP is unbanned.
        """
        duration_str = f"{duration} seconds" if duration != -1 else "PERMANENT"
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        message = (
            f":white_check_mark: *IP UNBANNED*\n"
            f">*IP:* `{ip}`\n"
            f">*Total Ban Count:* {ban_count}\n"
            f">*Previous Ban Duration:* {duration_str}\n"
            f">*Timestamp:* {timestamp}\n"
            f">*Note:* Next ban will be longer."
        )
        self._send(message)

    def send_global_alert(self, condition, rate, mean):
        """
        Send a Slack alert for a global traffic spike.
        No IP block — alert only.
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        message = (
            f":warning: *GLOBAL TRAFFIC SPIKE DETECTED*\n"
            f">*Condition:* {condition}\n"
            f">*Current Global Rate:* {rate} req/60s\n"
            f">*Baseline Mean:* {mean:.2f} req/s\n"
            f">*Action:* Alert only — no IP block\n"
            f">*Timestamp:* {timestamp}"
        )
        self._send(message)