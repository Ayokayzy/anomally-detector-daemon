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

        Deques are ordered chronologically — oldest timestamps sit on the left,
        newest on the right. When a new request arrives and `now` advances,
        anything on the left that falls outside the window becomes stale and must
        be removed so the count always reflects the last `window_size` seconds.

        Example (window_size = 60 seconds, now = 1000.0):

            Before eviction:
              dq = deque([930.0, 940.0, 950.0, 960.0, 980.0, 1000.0])

            Eviction loop:
              dq[0] = 930.0  →  now - 930.0 = 70.0 > 60  →  popleft()
              dq[0] = 940.0  →  now - 940.0 = 60.0 == 60 →  stop (not strictly >)

            After eviction:
              dq = deque([940.0, 950.0, 960.0, 980.0, 1000.0])

        The window now covers exactly [940.0, 1000.0] — 60 seconds of activity.

        popleft() on a deque is O(1), making eviction efficient even under
        very high request rates where many timestamps may need to be removed
        in a single pass.
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

        Why per-second counts instead of raw timestamps?
        -------------------------------------------------
        The baseline recorder thread (in main.py) samples the global sliding
        window once per second and passes the integer count here. Storing one
        integer per second is far more memory-efficient than storing individual
        request timestamps — under heavy traffic thousands of requests can arrive
        in a single second, but we only ever store one number for that second.
        This also makes the mean/stddev calculation cheaper: we sum a list of
        ~1800 integers rather than iterating over potentially millions of floats.

        How the 30-minute rolling window works:
        ----------------------------------------
        `self.history` is a deque of (timestamp, count) tuples. Each call to
        record() appends a new entry on the right. The while-loop immediately
        after the append evicts any entries from the left whose timestamp is
        older than `window_seconds` (30 × 60 = 1800 seconds).

        Over time the deque stabilises at ~1800 entries (one per second for
        30 minutes). As each new second arrives on the right, the oldest second
        drops off the left — the window slides forward without ever growing
        unboundedly in memory.

        Hourly slots:
        The same count is also appended to `self.hourly_slots[current_hour]`
        (keyed 0–23 by clock hour). _recalculate() prefers same-hour data when
        it has enough samples, because traffic patterns are strongly time-of-day
        dependent — mixing 3 AM data with 3 PM data inflates stddev and weakens
        detection sensitivity.

        Why recalculation is not triggered on every request:
        -------------------------------------------------------
        Mean and stddev change gradually. Recomputing statistics every single
        second (let alone every request) would waste CPU and produce identical
        results nearly every call. A 60-second recalculation window provides
        fresh-enough statistics (the baseline is at most 60 seconds stale)
        while keeping overhead negligible even under very high request volumes.
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
        Recompute effective_mean and effective_stddev from available traffic data.

        Data source priority:
        ----------------------
        1. Current-hour slot (preferred):
           If `self.hourly_slots[current_hour]` has at least `min_samples`
           entries, those are used exclusively. Same-hour data reflects the
           typical traffic pattern for this time of day. Traffic at 3 AM is
           structurally different from traffic at 3 PM — mixing them would
           inflate stddev, raising the bar for z-score detection and letting
           attackers hide in the noise.

        2. Rolling window (fallback):
           If the current hour lacks enough data (e.g., the first 30 seconds
           after midnight, or when the daemon first starts), all data in the
           30-minute rolling window is used regardless of hour. This ensures
           the detector stays operational during warm-up without crashing.

        Floor values of 1.0:
        ----------------------
        After computing mean and stddev from the data, both values are clamped
        to a minimum of 1.0 via `max(value, 1.0)`. Two reasons:

          - A mean of 0 would imply "zero requests per second is normal", which
            makes the z-score meaningless on any non-zero traffic.
          - A stddev of 0 means all sampled counts were identical. While
            _compute_zscore() handles the zero-division case by returning 0,
            a stddev floor of 1.0 keeps the z-score scaled sensibly and avoids
            completely disabling statistical detection during dead-quiet periods.

        Together the floors mean: "assume at least one request per second with
        one request per second of variability" — a safe conservative minimum
        that prevents false positives on legitimate zero-traffic windows.

        Why recalculate every 60 seconds instead of every request:
        ------------------------------------------------------------
        Mean and stddev change slowly. Recalculating on every single request
        would be pure waste — the result would be nearly identical 999 times
        out of 1000. One recalculation per 60 seconds produces statistics that
        are at most 60 seconds stale, which is accurate enough for the
        detector's z-score checks while keeping CPU overhead near zero even
        under attack-level request volumes.
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