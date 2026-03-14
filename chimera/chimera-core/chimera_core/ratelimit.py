import time
from threading import Lock

class RateLimiter:
    def __init__(self, requests_per_second: float):
        self.requests_per_second = requests_per_second
        self.tokens = self.requests_per_second
        self.last_refill = time.monotonic()
        self.lock = Lock()

    def acquire(self) -> bool:
        with self.lock:
            self._refill()
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        
        # Calculate how many tokens to add, considering fractional tokens
        tokens_to_add = elapsed * self.requests_per_second
        
        if tokens_to_add > 0:
            self.tokens = min(self.tokens + tokens_to_add, self.requests_per_second)
            self.last_refill = now
