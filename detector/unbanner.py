import time
import logging

logger = logging.getLogger(__name__)


class Unbanner:
    """
    Runs in a background thread.
    Checks every 30 seconds for expired bans and lifts them.
    Sends Slack notifications on every unban.
    """

    def __init__(self, blocker, notifier, audit_logger):
        self.blocker = blocker
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.check_interval = 30  # check every 30 seconds

    def run(self):
        """
        Main unbanner loop. Runs forever in a background thread.
        """
        logger.info("Unbanner thread started.")

        while True:
            self._check_and_unban()
            time.sleep(self.check_interval)

    def _check_and_unban(self):
        """
        Check for expired bans and unban them.
        """
        expired_ips = self.blocker.get_expired_bans()

        for ip in expired_ips:
            ban_info = self.blocker.unban(ip)

            if ban_info:
                # Write to audit log
                self.audit_logger.log_unban(
                    ip=ip,
                    ban_count=ban_info["ban_count"],
                    duration=ban_info["duration"]
                )

                # Send Slack notification
                self.notifier.send_unban_alert(
                    ip=ip,
                    ban_count=ban_info["ban_count"],
                    duration=ban_info["duration"]
                )

                logger.info(
                    f"[UNBANNED] IP: {ip} | "
                    f"Ban count: {ban_info['ban_count']} | "
                    f"Next ban duration will be longer."
                )