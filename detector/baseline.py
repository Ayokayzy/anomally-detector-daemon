import time
import math
import logging
from collections import deque, defaultdict

logger = logging.getLogger(__name__)


class SlidingWindow:
    """
    Tracks request rates using deque-based windows over the last 60 seconds.
    Two windows are maintained:
      - per_ip: one deque per IP address
      - global_window: one deque for all traffic combined
    """

    def __init__(self, window_size=60):
        # How many seconds to look back
        self.window_size = window_size

        # One deque per IP — stores timestamps of each request
        # defaultdict automatically creates a new deque for any new IP
        self.per_ip = defaultdict(deque)

        # One deque for all traffic combined
        self.global_window = deque()

        # Track error counts per IP (4xx and 5xx responses)
        self.per_ip_errors = defaultdict(deque)

    def _evict(self, dq, now):
        """
        Remove entries older than window_size seconds from the left of the deque.
        This is what makes the window 'slide' forward in time.
        """
        while dq and now - dq[0] > self.window_size:
            dq.popleft()

    def add(self, source_ip, status_code):
        """
        Record a new request from source_ip with the given status_code.
        Updates both the per-IP window and the global window.
        """
        now = time.time()

        # Add to per-IP window
        self.per_ip[source_ip].append(now)
        self._evict(self.per_ip[source_ip], now)

        # Add to global window
        self.global_window.append(now)
        self._evict(self.global_window, now)

        # Track errors (4xx and 5xx) per IP
        if status_code >= 400:
            self.per_ip_errors[source_ip].append(now)
            self._evict(self.per_ip_errors[source_ip], now)

    def get_ip_rate(self, source_ip):
        """
        Return the number of requests from this IP in the last window_size seconds.
        """
        now = time.time()
        self._evict(self.per_ip[source_ip], now)
        return len(self.per_ip[source_ip])

    def get_global_rate(self):
        """
        Return the total number of requests from all IPs in the last window_size seconds.
        """
        now = time.time()
        self._evict(self.global_window, now)
        return len(self.global_window)

    def get_ip_error_rate(self, source_ip):
        """
        Return the number of 4xx/5xx responses from this IP in the last window_size seconds.
        """
        now = time.time()
        self._evict(self.per_ip_errors[source_ip], now)
        return len(self.per_ip_errors[source_ip])

    def get_top_ips(self, n=10):
        """
        Return the top n IPs by request count in the current window.
        Used by the dashboard to show top 10 source IPs.
        """
        now = time.time()
        counts = {}

        for ip, dq in self.per_ip.items():
            self._evict(dq, now)
            if dq:
                counts[ip] = len(dq)

        # Sort by count descending and return top n
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]


class RollingBaseline:
    """
    Computes mean and stddev from a rolling 30-minute window of
    per-second request counts. Recalculated every 60 seconds.
    Maintains per-hour slots and prefers the current hour's data
    when it has enough samples.
    """

    def __init__(self, window_minutes=30, recalc_interval=60, min_samples=30):
        # How many minutes of history to keep
        self.window_minutes = window_minutes
        self.window_seconds = window_minutes * 60

        # How often to recalculate mean and stddev (seconds)
        self.recalc_interval = recalc_interval

        # Minimum samples before baseline is considered reliable
        self.min_samples = min_samples

        # Rolling window of (timestamp, per_second_count) tuples
        self.history = deque()

        # Per-hour slots — key is the hour (0-23), value is list of counts
        self.hourly_slots = defaultdict(list)

        # Current computed baseline values
        self.effective_mean = 1.0   # floor value, never zero
        self.effective_stddev = 1.0 # floor value, never zero

        # Timestamp of last recalculation
        self.last_recalc = time.time()

        # Per-second counter — how many requests happened this second
        self.current_second = int(time.time())
        self.current_count = 0

        logger.info("RollingBaseline initialized.")

    def record(self, count, audit_logger=None):
        """
        Record a per-second request count into the rolling history.
        """
        now = time.time()
        current_hour = int(time.strftime("%H"))

        self.history.append((now, count))
        self.hourly_slots[current_hour].append(count)

        while self.history and now - self.history[0][0] > self.window_seconds:
            self.history.popleft()

        if now - self.last_recalc >= self.recalc_interval:
            self._recalculate(current_hour, audit_logger=audit_logger)
            self.last_recalc = now

    def _recalculate(self, current_hour, audit_logger=None):
        """
        Recompute mean and stddev.
        Prefer current hour's data if it has enough samples,
        otherwise fall back to the full rolling window.
        """
        hourly_data = self.hourly_slots[current_hour]

        if len(hourly_data) >= self.min_samples:
            data = hourly_data
            source = f"hour-{current_hour}"
        else:
            data = [count for _, count in self.history]
            source = "rolling-window"

        if len(data) < 2:
            logger.info("Not enough data to recalculate baseline yet.")
            return

        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        stddev = math.sqrt(variance)

        self.effective_mean = max(mean, 1.0)
        self.effective_stddev = max(stddev, 1.0)

        logger.info(
            f"[BASELINE RECALC] source={source} | "
            f"samples={len(data)} | "
            f"mean={self.effective_mean:.2f} | "
            f"stddev={self.effective_stddev:.2f}"
        )

        # Write to audit log if provided
        if audit_logger:
            audit_logger.log_baseline_recalc(
                source=source,
                samples=len(data),
                mean=self.effective_mean,
                stddev=self.effective_stddev
            )
        
    def get_baseline(self):
        """
        Return current effective mean and stddev.
        """
        return self.effective_mean, self.effective_stddev