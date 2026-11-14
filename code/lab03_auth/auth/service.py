from auth.hotp import HotpVerifier
from auth.lockout import PairLockout
from auth.passwords import hash_password, verify_password


class AuthService:
    def __init__(self, lockout: PairLockout | None = None) -> None:
        self._users: dict[str, tuple[str, HotpVerifier]] = {}
        self.lockout = lockout or PairLockout()

    def register(self, account: str, password: str, secret: bytes) -> None:
        self._users[account] = (hash_password(password), HotpVerifier(secret))

    def login(
        self, account: str, ip: str, password: str, code: str, now: float
    ) -> tuple[bool, str]:
        if not self.lockout.is_allowed(account, ip, now):
            return False, "відхилено без перевірки"
        ok, reason = self._check(account, password, code)
        self.lockout.record_attempt(account, ip, ok, now)
        return ok, reason

    def _check(self, account: str, password: str, code: str) -> tuple[bool, str]:
        user = self._users.get(account)
        if user is None or not verify_password(user[0], password):
            return False, "хибний логін або пароль"
        if not user[1].verify(code):
            return False, "хибний код HOTP"
        return True, "вхід виконано"
