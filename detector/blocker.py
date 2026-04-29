import subprocess
import logging
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class Blocker:
    """
    Manages iptables DROP rules for banned IPs.
    Tracks ban counts per IP to implement the backoff unban schedule.
    """

    def __init__(self, config):
        # Unban schedule in seconds from config.yaml
        # [600, 1800, 7200, -1] = [10min, 30min, 2hr, permanent]
        self.unban_schedule = config["blocking"]["unban_schedule"]

        # Currently banned IPs
        # Structure: { ip: { "banned_at": timestamp, "ban_count": int, "duration": int } }
        self.banned_ips = {}

    def is_banned(self, ip):
        """
        Check if an IP is currently banned.
        """
        return ip in self.banned_ips

    def ban(self, ip, condition, rate, mean):
        """
        Add an iptables DROP rule for the given IP.
        Determines ban duration based on how many times this IP
        has been banned before (backoff schedule).
        Returns the ban duration in seconds, or -1 for permanent.
        """
        # If already banned, don't ban again
        if self.is_banned(ip):
            return None

        # Get ban count for this IP (how many times banned before)
        ban_count = self.banned_ips.get(ip, {}).get("ban_count", 0)

        # Determine duration from backoff schedule
        if ban_count < len(self.unban_schedule):
            duration = self.unban_schedule[ban_count]
        else:
            duration = -1  # permanent

        # Add iptables DROP rule
        success = self._add_iptables_rule(ip)

        if not success:
            logger.error(f"Failed to add iptables rule for {ip}")
            return None

        # Record the ban
        self.banned_ips[ip] = {
            "banned_at": time.time(),
            "ban_count": ban_count + 1,
            "duration": duration,
            "condition": condition,
            "rate": rate,
            "mean": mean,
        }

        duration_str = f"{duration}s" if duration != -1 else "permanent"
        logger.warning(
            f"[BAN] IP: {ip} | "
            f"Condition: {condition} | "
            f"Rate: {rate} | "
            f"Mean: {mean:.2f} | "
            f"Duration: {duration_str} | "
            f"Ban count: {ban_count + 1}"
        )

        return duration

    def unban(self, ip):
        """
        Remove the iptables DROP rule for the given IP.
        Returns ban info for notification purposes.
        """
        if not self.is_banned(ip):
            return None

        ban_info = self.banned_ips[ip]

        # Remove iptables rule
        success = self._remove_iptables_rule(ip)

        if not success:
            logger.error(f"Failed to remove iptables rule for {ip}")
            return None

        # Remove from banned list
        del self.banned_ips[ip]

        logger.info(
            f"[UNBAN] IP: {ip} | "
            f"Ban count was: {ban_info['ban_count']} | "
            f"Was banned for: {ban_info['duration']}s"
        )

        return ban_info

    def get_expired_bans(self):
        """
        Return list of IPs whose ban duration has expired.
        Permanent bans (duration=-1) are never expired.
        """
        now = time.time()
        expired = []

        for ip, info in self.banned_ips.items():
            duration = info["duration"]

            # Skip permanent bans
            if duration == -1:
                continue

            # Check if ban has expired
            if now - info["banned_at"] >= duration:
                expired.append(ip)

        return expired

    def get_banned_ips(self):
        """
        Return all currently banned IPs with their info.
        Used by the dashboard.
        """
        return dict(self.banned_ips)

    def _add_iptables_rule(self, ip):
        """
        Run the iptables command to DROP traffic from this IP.
        Uses -I to INSERT at the top of the chain (highest priority).
        """
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            logger.info(f"iptables DROP rule added for {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables error for {ip}: {e.stderr.decode()}")
            return False

    def _remove_iptables_rule(self, ip):
        """
        Run the iptables command to remove the DROP rule for this IP.
        """
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            logger.info(f"iptables DROP rule removed for {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables error removing {ip}: {e.stderr.decode()}")
            return False