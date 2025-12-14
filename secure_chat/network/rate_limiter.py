import time
import logging
from collections import defaultdict
from config import MAX_REQUESTS_PER_MINUTE

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, max_requests=MAX_REQUESTS_PER_MINUTE, window=60):
        self.requests = defaultdict(list)
        self.max_requests = max_requests
        self.window = window
    
    def allow(self, addr):
        now = time.time()
        addr_key = f"{addr[0]}:{addr[1]}"
        self.requests[addr_key] = [t for t in self.requests[addr_key] if now - t < self.window]
        
        if len(self.requests[addr_key]) >= self.max_requests:
            logger.warning(f"⚠ Rate limit exceeded for {addr_key}")
            return False
        
        self.requests[addr_key].append(now)
        return True