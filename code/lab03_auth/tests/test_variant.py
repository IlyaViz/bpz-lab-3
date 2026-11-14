import base64
import hashlib
import hmac
import os
import sys

# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
os.environ["AUTH_PEPPER"] = "lab3-test-pepper"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from auth import passwords
from auth.anderson import entropy_bits, min_length, required_space
from auth.hotp import HotpToken, HotpVerifier, hotp
from auth.lockout import PairLockout
from auth.passwords import hash_password, hash_password_insecure, verify_password
from auth.service import AuthService

# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
SECRET = b"12345678901234567890"
RFC_CODES = [
    "755224",
    "287082",
    "359152",
    "969429",
    "338314",
    "254676",
    "287922",
    "162583",
    "399871",
    "520489",
]
HOME, ATTACKER = "198.51.100.7", "203.0.113.5"
PAIR = ("student", ATTACKER)
PASSWORD = "Lab3-test-pass"


def locked_pair() -> PairLockout:
    lock = PairLockout()
    for t in range(5):
        lock.record_attempt(*PAIR, False, t)
    return lock


def test_anderson_control_example():
    g = required_space(10, 90, 1e-6)
    assert g == pytest.approx(1.296e12)
    assert min_length(g, 95) == 7
    assert round(entropy_bits(95, 7), 1) == 46.0


def test_anderson_variant():
    g = required_space(6, 60, 1e-7)
    assert g == pytest.approx(5.184e12)
    assert [min_length(g, a) for a in (26, 62, 95)] == [9, 8, 7]


def test_hash_roundtrip():
    assert verify_password(hash_password("correct horse"), "correct horse")


def test_wrong_password_rejected():
    stored = hash_password("correct horse")
    assert not verify_password(stored, "wrong")
    assert not verify_password(stored, "correct horse ")


def test_salt_is_unique():
    a, b = hash_password("same"), hash_password("same")
    assert a != b
    assert a.split("$")[2] != b.split("$")[2]


def test_record_format():
    algo, params, salt, dk = hash_password("x").split("$")
    assert algo == "scrypt" and params == "n=16384,r=8,p=1"
    assert len(base64.b64decode(salt)) == 16
    assert len(base64.b64decode(dk)) == 32


def test_pepper_is_needed(monkeypatch):
    stored = hash_password("correct horse")
    monkeypatch.setattr(passwords, "PEPPER", b"")
    assert not verify_password(stored, "correct horse")
    monkeypatch.setattr(passwords, "PEPPER", b"other-pepper")
    assert not verify_password(stored, "correct horse")


def test_broken_record_rejected():
    assert not verify_password("garbage", "x")
    assert not verify_password("md5$n=1,r=1,p=1$AAAA$AAAA", "x")


def test_compare_digest_is_used(monkeypatch):
    calls = []
    original = hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return original(a, b)

    monkeypatch.setattr(passwords.hmac, "compare_digest", spy)
    verify_password(hash_password("x"), "y")
    assert len(calls) == 1


def test_insecure_repeats():
    a = hash_password_insecure("password123")
    assert a == hash_password_insecure("password123")
    assert a == hashlib.sha256(b"password123").hexdigest()
    assert hash_password("password123") != hash_password("password123")


def test_lockout_after_limit():
    lock = PairLockout()
    for t in range(4):
        lock.record_attempt(*PAIR, False, t)
    assert lock.is_allowed(*PAIR, 4)
    lock.record_attempt(*PAIR, False, 4)
    assert not lock.is_allowed(*PAIR, 4)


def test_lockout_expires():
    lock = locked_pair()
    assert not lock.is_allowed(*PAIR, 4 + 899)
    assert lock.is_allowed(*PAIR, 4 + 900)


def test_lockout_is_per_pair():
    lock = locked_pair()
    assert lock.is_allowed("student", HOME, 5)
    assert lock.is_allowed("teacher", ATTACKER, 5)


def test_success_resets_counter():
    lock = PairLockout()
    for t in range(4):
        lock.record_attempt(*PAIR, False, t)
    lock.record_attempt(*PAIR, True, 4)
    for t in range(5, 9):
        lock.record_attempt(*PAIR, False, t)
    assert lock.failures(*PAIR) == 4
    assert lock.is_allowed(*PAIR, 9)


def test_hotp_rfc_vectors():
    assert [hotp(SECRET, c) for c in range(10)] == RFC_CODES


def test_hotp_matches_pyotp():
    pyotp = pytest.importorskip("pyotp")
    other = pyotp.HOTP(base64.b32encode(SECRET).decode())
    assert all(other.at(c) == hotp(SECRET, c) for c in range(100))


def test_hotp_window_and_replay():
    server = HotpVerifier(SECRET)
    assert server.verify(RFC_CODES[2])
    assert server.counter == 3
    assert not server.verify(RFC_CODES[2])
    assert not server.verify(RFC_CODES[6])
    assert server.verify(RFC_CODES[5])


def test_login_needs_both_factors():
    service = AuthService()
    service.register("student", PASSWORD, SECRET)
    token = HotpToken(SECRET)
    assert service.login("student", HOME, PASSWORD, token.next_code(), 0)[0]
    code = token.next_code()
    reason = service.login("student", HOME, "wrong", code, 1)[1]
    assert reason == "хибний логін або пароль"
    reason = service.login("nobody", HOME, PASSWORD, code, 2)[1]
    assert reason == "хибний логін або пароль"
    reason = service.login("student", HOME, PASSWORD, "000000", 3)[1]
    assert reason == "хибний код HOTP"
    assert service.login("student", HOME, PASSWORD, code, 4)[0]


def test_wrong_codes_lock_pair():
    service = AuthService()
    service.register("student", PASSWORD, SECRET)
    for t in range(5):
        service.login("student", ATTACKER, PASSWORD, "000000", t)
    ok, reason = service.login("student", ATTACKER, PASSWORD, RFC_CODES[0], 5)
    assert not ok and reason == "відхилено без перевірки"
    assert service.login("student", HOME, PASSWORD, RFC_CODES[0], 6)[0]
