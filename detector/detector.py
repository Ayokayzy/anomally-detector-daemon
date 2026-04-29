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
        Compute how many standard deviations the current rate is above the baseline.

        Formula:  z = (x - μ) / σ
          x  = current_rate  — the observed request rate right now
          μ  = mean          — the expected "normal" rate from the rolling baseline
          σ  = stddev        — the expected variability around that mean

        What different z-score values mean in plain English:
          z < 1.0  — Normal. The rate is within one standard deviation of
                     the mean; this is everyday traffic variation.
          z = 2.0  — Elevated. Unusual but could still be organic — e.g.,
                     a blog post going mildly viral.
          z = 3.0  — Alert threshold (default z_score_threshold in config).
                     In a normal distribution only ~0.13% of values exceed
                     three sigma, so reaching this level is very unlikely to
                     be innocent.
          z > 5.0  — Severe spike. Almost certainly a scan, flood, or attack.

        Why z-score is better than a fixed threshold:
          A hardcoded limit like "flag if > 100 req/60s" is fragile. During
          low-traffic hours an attacker can stay just under it; during a busy
          period it triggers false positives on legitimate users.

          Z-score is self-calibrating: the threshold adapts to whatever
          traffic level the server is currently experiencing. A busy server
          with mean=200 and stddev=40 requires a rate of ~320 to reach z=3,
          whereas a quiet server with mean=5 and stddev=2 triggers at only
          ~11. The same threshold value (3.0) works correctly across both
          scenarios without any manual tuning.

        Returns 0 when stddev is 0 (all historical counts are identical),
        avoiding division-by-zero. In this edge case no anomaly is detectable
        by z-score and the rate-multiplier condition acts as backup.
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

        Two independent conditions are evaluated; the first one to fire wins
        and the result is returned immediately (the second is not checked):

        Condition 1 — Z-score threshold (fires first):
          If the IP's rate is more than `effective_z` standard deviations above
          the baseline mean it is flagged. This is the primary statistical
          detector; it is evaluated first because it is the most principled
          measure of how abnormal the traffic really is relative to recent
          history.

        Condition 2 — Rate multiplier safety net (fires second):
          Even if the z-score is below the threshold (which can happen when
          stddev is very large due to an already-noisy traffic period), if the
          IP's rate is more than 5× the baseline mean it is still flagged. This
          catches extreme spikes that the z-score alone might miss when the
          baseline is in an unusually variable state.

        Error surge tightening (evaluated before both conditions):
          Before computing the z-score, the method checks whether the IP's
          4xx/5xx error rate is at least `error_multiplier` (3×) times the
          baseline error rate. If so, the IP's strike count is incremented.
          `_get_effective_threshold()` then returns the tightened z-score (2.0
          instead of 3.0) for this IP from now on. An IP already probing with
          bad requests earns a lower tolerance — a smaller rate spike is enough
          to trigger a ban.
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
        Check if total traffic across all IPs is anomalous.
        Returns a dict describing the anomaly, or None if normal.

        Uses the same two-condition logic as check_ip() (z-score threshold
        then rate-multiplier fallback), but operates on the aggregate request
        rate from all source IPs rather than any single IP's rate.

        Why a global anomaly triggers a Slack alert only — never an IP ban:
        ----------------------------------------------------------------------
        A global traffic spike is a fleet-wide signal, not a per-IP signal.
        It can be caused by many different IPs each sending a perfectly normal
        number of requests at the same time — for example, a viral news article,
        a scheduled mass notification to all users, a legitimate product launch,
        or a CDN cache miss that sends every user to the origin simultaneously.

        In these cases every individual IP's z-score and rate would be below the
        ban threshold, so no per-IP anomaly fires. But the aggregate sum tips the
        global z-score over the threshold.

        Banning one or more IPs in this scenario would be both incorrect (no
        single IP is misbehaving) and pointless (hundreds of other IPs continue
        the traffic). It would instead harm legitimate users.

        The correct response is to alert the operator (via Slack) so they can
        look at the dashboard, assess whether the spike is expected or malicious,
        and take a considered manual action — such as scaling the infrastructure,
        enabling a WAF rule, or simply confirming it is harmless. Automated
        banning here would generate false positives and erode operator trust
        in the system.
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