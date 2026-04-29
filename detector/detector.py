import logging

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Detects anomalies using z-score and rate multiplier checks.
    Flags per-IP anomalies and global traffic spikes separately.
    """

    def __init__(self, config):
        # Thresholds loaded from config.yaml — never hardcoded
        self.z_threshold = config["detection"]["z_score_threshold"]
        self.rate_multiplier = config["detection"]["rate_multiplier"]
        self.error_multiplier = config["detection"]["error_surge_multiplier"]
        self.tightened_z = config["detection"]["tightened_z_threshold"]

        # Track how many times each IP has been flagged
        # Used for error surge threshold tightening
        self.ip_strike_counts = {}

    def _compute_zscore(self, current_rate, mean, stddev):
        """
        Calculate z-score for the current rate against the baseline.
        """
        if stddev == 0:
            return 0
        return (current_rate - mean) / stddev

    def _get_effective_threshold(self, source_ip):
        """
        Return the effective z-score threshold for this IP.
        If the IP has had an error surge, use the tightened threshold.
        """
        if self.ip_strike_counts.get(source_ip, 0) > 0:
            return self.tightened_z
        return self.z_threshold

    def check_ip(self, source_ip, ip_rate, ip_error_rate, mean, stddev, baseline_error_rate):
        """
        Check if a single IP is behaving anomalously.
        Returns a dict describing the anomaly, or None if normal.
        """
        # Check for error surge first — tighten threshold if detected
        if baseline_error_rate > 0:
            error_ratio = ip_error_rate / baseline_error_rate
            if error_ratio >= self.error_multiplier:
                self.ip_strike_counts[source_ip] = (
                    self.ip_strike_counts.get(source_ip, 0) + 1
                )
                logger.warning(
                    f"[ERROR SURGE] IP: {source_ip} | "
                    f"Error rate: {ip_error_rate} | "
                    f"Baseline error rate: {baseline_error_rate:.2f} | "
                    f"Ratio: {error_ratio:.2f}x | "
                    f"Thresholds tightened."
                )

        # Get effective z-score threshold for this IP
        effective_z = self._get_effective_threshold(source_ip)

        # Compute z-score
        z_score = self._compute_zscore(ip_rate, mean, stddev)

        # Condition 1 — z-score exceeds threshold
        if z_score > effective_z:
            return {
                "type": "ip",
                "source_ip": source_ip,
                "condition": f"z-score {z_score:.2f} > {effective_z}",
                "current_rate": ip_rate,
                "mean": mean,
                "stddev": stddev,
                "z_score": z_score,
            }

        # Condition 2 — rate exceeds 5x baseline mean
        if mean > 0 and ip_rate > self.rate_multiplier * mean:
            return {
                "type": "ip",
                "source_ip": source_ip,
                "condition": f"rate {ip_rate} > {self.rate_multiplier}x mean ({mean:.2f})",
                "current_rate": ip_rate,
                "mean": mean,
                "stddev": stddev,
                "z_score": z_score,
            }

        return None

    def check_global(self, global_rate, mean, stddev):
        """
        Check if overall traffic is anomalous.
        Returns a dict describing the anomaly, or None if normal.
        """
        z_score = self._compute_zscore(global_rate, mean, stddev)

        # Condition 1 — z-score exceeds threshold
        if z_score > self.z_threshold:
            return {
                "type": "global",
                "condition": f"z-score {z_score:.2f} > {self.z_threshold}",
                "current_rate": global_rate,
                "mean": mean,
                "stddev": stddev,
                "z_score": z_score,
            }

        # Condition 2 — rate exceeds 5x baseline mean
        if mean > 0 and global_rate > self.rate_multiplier * mean:
            return {
                "type": "global",
                "condition": f"rate {global_rate} > {self.rate_multiplier}x mean ({mean:.2f})",
                "current_rate": global_rate,
                "mean": mean,
                "stddev": stddev,
                "z_score": z_score,
            }

        return None