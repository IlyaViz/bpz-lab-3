import base64
import math
import os
import time

# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
os.environ.setdefault("AUTH_PEPPER", "lab3-demo-pepper")

from auth import passwords
from auth.anderson import entropy_bits, min_length, required_space
from auth.hotp import HotpToken, HotpVerifier, hotp
from auth.lockout import PairLockout
from auth.passwords import hash_password, hash_password_insecure, verify_password
from auth.service import AuthService

RATE, PERIOD, PROBABILITY = 6, 60, 1e-7
ALPHABETS = (26, 62, 95)

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
PASSWORD = "Lab3-demo-pass"
HOME, ATTACKER = "198.51.100.7", "203.0.113.5"


def anderson() -> None:
    print("1. Формула Андерсона")
    g = required_space(10, 90, 1e-6)
    length = min_length(g, 95)
    print(
        f"контрольний приклад: G >= {g:.3e}, L(95) = {length}, "
        f"H = {entropy_bits(95, length):.1f} біт"
    )
    g = required_space(RATE, PERIOD, PROBABILITY)
    print(f"варіант 4: R = {RATE} /хв, T = {PERIOD} діб, P = {PROBABILITY:g}")
    print(f"R*T = {RATE * PERIOD * 24 * 60} спроб, G >= R*T/P = {g:.3e}")
    print("    A  log(G)/log(A)  L  H, біт")
    for a in ALPHABETS:
        length = min_length(g, a)
        ratio = math.log(g) / math.log(a)
        print(f"  {a:3} {ratio:13.2f} {length:3} {entropy_bits(a, length):7.1f}")


def spaced(value: float) -> str:
    return f"{value:,.0f}".replace(",", " ")


def average(func, arg, runs: int) -> float:
    start = time.perf_counter()
    for _ in range(runs):
        func(arg)
    return (time.perf_counter() - start) / runs


def verify_with_pepper(stored: str, password: str, pepper: bytes) -> bool:
    saved = passwords.PEPPER
    passwords.PEPPER = pepper
    try:
        return verify_password(stored, password)
    finally:
        passwords.PEPPER = saved


def storage() -> None:
    n, r, p = passwords.SCRYPT_N, passwords.SCRYPT_R, passwords.SCRYPT_P
    print(f"\n2. Зберігання паролів: scrypt, N = {n}, r = {r}, p = {p}")
    stored = hash_password(PASSWORD)
    print("запис:", stored)
    print(
        f"сіль {passwords.SALT_BYTES} байтів, ключ {passwords.KEY_BYTES} байти, "
        f"пам'ять 128*r*N = {128 * r * n // 2**20} МіБ"
    )
    print("правильний пароль:", verify_password(stored, PASSWORD))
    print("хибний пароль:", verify_password(stored, "Lab3-demo-pas"))
    print("два записи одного пароля різні:", hash_password(PASSWORD) != stored)
    no_pepper = verify_with_pepper(stored, PASSWORD, b"")
    print("правильний пароль без перцю:", no_pepper)
    slow = average(hash_password, PASSWORD, 20)
    fast = average(hash_password_insecure, PASSWORD, 100000)
    print(f"hash_password: {slow * 1e3:.1f} мс (середнє з 20)")
    print(f"hash_password_insecure: {fast * 1e6:.2f} мкс (середнє з 100000)")
    print(f"відношення часу scrypt / SHA-256: {spaced(slow / fast)}")
    print("перебір на одному ядрі, паролів за секунду:")
    print(f"  scrypt {spaced(1 / slow)}, SHA-256 {spaced(1 / fast)}")


def insecure() -> None:
    print("\n3. Порівняння з вразливим зберіганням, пароль password123")
    a = hash_password_insecure("password123")
    b = hash_password_insecure("password123")
    print("SHA-256 #1:", a)
    print("SHA-256 #2:", b)
    print("SHA-256 однакові:", a == b)
    c = hash_password("password123")
    d = hash_password("password123")
    print("scrypt #1:", c)
    print("scrypt #2:", d)
    print("scrypt різні:", c != d)


def lockout() -> None:
    print('\n4. Блокування за парою "обліковий запис + IP": 5 невдач -> 15 хв')
    service = AuthService()
    service.register("student", PASSWORD, SECRET)
    token = HotpToken(SECRET)
    steps = [
        (0, HOME, PASSWORD, token.next_code()),
        (10, ATTACKER, "qwerty", "000000"),
        (11, ATTACKER, "123456", "000000"),
        (12, ATTACKER, "password", "000000"),
        (13, ATTACKER, "student2026", "000000"),
        (14, ATTACKER, "letmein", "000000"),
        (15, ATTACKER, PASSWORD, "000000"),
        (20, HOME, PASSWORD, token.next_code()),
        (30, HOME, PASSWORD, "000000"),
        (31, HOME, PASSWORD, token.next_code()),
        (913, ATTACKER, "dragon", "000000"),
        (914, ATTACKER, "dragon", "000000"),
    ]
    print("   t  IP            пароль       код    результат                стан")
    for now, ip, password, code in steps:
        _, reason = service.login("student", ip, password, code, now)
        if service.lockout.is_allowed("student", ip, now):
            state = f"невдач {service.lockout.failures('student', ip)}"
        else:
            state = "блок"
        shown = "правильний" if password == PASSWORD else password
        print(f"{now:4}  {ip:<12}  {shown:<12} {code} {reason:<24} {state}")
    limit = PairLockout()
    pair = ("student", ATTACKER)
    for t in range(4):
        limit.record_attempt(*pair, False, t)
    print("після 4 невдач дозволено:", limit.is_allowed(*pair, 4))
    limit.record_attempt(*pair, False, 4)
    print("після 5 невдач дозволено:", limit.is_allowed(*pair, 4))
    print("через 899 с після блокування дозволено:", limit.is_allowed(*pair, 903))
    print("через 900 с після блокування дозволено:", limit.is_allowed(*pair, 904))
    other = limit.is_allowed("student", HOME, 5)
    print("той самий запис з іншої IP дозволено:", other)
    rate = limit.max_failures / (limit.lock_seconds / 60)
    print("вплив на формулу Андерсона, A = 95:")
    rates = [("без блокування", RATE), ("1 IP", rate), ("100 IP", 100 * rate)]
    for label, r in rates:
        g = required_space(r, PERIOD, PROBABILITY)
        length = min_length(g, 95)
        print(f"  {label}: R = {r:.2f} /хв, G >= {g:.3e}, L = {length}")


def second_factor() -> None:
    print("\n5. Другий фактор HOTP (RFC 4226), секрет 12345678901234567890")
    print("  лічильник  очікувано  факт    збіг")
    for counter, expected in enumerate(RFC_CODES):
        code = hotp(SECRET, counter)
        print(f"  {counter:9}  {expected}     {code}  {code == expected}")
    try:
        import pyotp

        other = pyotp.HOTP(base64.b32encode(SECRET).decode())
        same = all(other.at(c) == hotp(SECRET, c) for c in range(10))
        print("звірка з pyotp для лічильників 0-9:", same)
    except ImportError:
        print("звірка з pyotp: бібліотеку не встановлено")
    server = HotpVerifier(SECRET)
    token = HotpToken(SECRET)
    token.next_code()
    token.next_code()
    code = token.next_code()
    print(f"токен згенерував коди 0 і 1 без входу, код 2 = {code}")
    accepted = server.verify(code)
    print(f"сервер (лічильник 0, вікно {server.window}) приймає код 2:", accepted)
    print("лічильник сервера після входу:", server.counter)
    print("повторне пред'явлення того самого коду:", server.verify(code))
    print("код лічильника 6 (поза вікном 3-5):", server.verify(hotp(SECRET, 6)))


if __name__ == "__main__":
    anderson()
    storage()
    insecure()
    lockout()
    second_factor()
