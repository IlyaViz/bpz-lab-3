import hashlib
import hmac

DIGITS = 6
WINDOW = 3


def hotp(secret: bytes, counter: int, digits: int = DIGITS) -> str:
    mac = hmac.new(secret, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


class HotpToken:
    def __init__(self, secret: bytes, counter: int = 0) -> None:
        self._secret = secret
        self.counter = counter

    def next_code(self) -> str:
        code = hotp(self._secret, self.counter)
        self.counter += 1
        return code


class HotpVerifier:
    def __init__(self, secret: bytes, counter: int = 0) -> None:
        self._secret = secret
        self.counter = counter
        self.window = WINDOW

    def verify(self, code: str) -> bool:
        for c in range(self.counter, self.counter + self.window):
            if hmac.compare_digest(hotp(self._secret, c).encode(), code.encode()):
                self.counter = c + 1
                return True
        return False
