MAX_FAILURES = 5
LOCK_SECONDS = 15 * 60


class PairLockout:
    def __init__(
        self, max_failures: int = MAX_FAILURES, lock_seconds: int = LOCK_SECONDS
    ) -> None:
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._failures: dict[tuple[str, str], int] = {}
        self._locked_until: dict[tuple[str, str], float] = {}

    def record_attempt(self, account: str, ip: str, ok: bool, now: float) -> None:
        key = (account, ip)
        if ok:
            self._failures.pop(key, None)
            return
        count = self._failures.get(key, 0) + 1
        if count >= self.max_failures:
            self._locked_until[key] = now + self.lock_seconds
            count = 0
        self._failures[key] = count

    def is_allowed(self, account: str, ip: str, now: float) -> bool:
        until = self._locked_until.get((account, ip))
        return until is None or now >= until

    def failures(self, account: str, ip: str) -> int:
        return self._failures.get((account, ip), 0)
