import pytest
import time
from chimera_core.ratelimit import RateLimiter

def test_rate_limiter_allows_burst():
    limiter = RateLimiter(requests_per_second=10)
    # Should be able to acquire tokens up to the limit initially
    for _ in range(10):
        assert limiter.acquire() is True

def test_rate_limiter_blocks_when_exceeded():
    limiter = RateLimiter(requests_per_second=10)
    for _ in range(10):
        assert limiter.acquire() is True
    # The 11th attempt should fail
    assert limiter.acquire() is False

def test_rate_limiter_refills_over_time():
    limiter = RateLimiter(requests_per_second=10)
    for _ in range(10):
        limiter.acquire()
    
    # After 0.1 seconds, one token should have refilled
    time.sleep(0.1)
    assert limiter.acquire() is True
    # The next one should fail immediately after
    assert limiter.acquire() is False

    # After another 0.2 seconds, two more tokens should be available
    time.sleep(0.2)
    assert limiter.acquire() is True
    assert limiter.acquire() is True
    assert limiter.acquire() is False
