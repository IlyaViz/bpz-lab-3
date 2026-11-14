"""Зберігання та перевірка паролів — КАРКАС для лабораторної роботи 3.

Здобувач реалізує функцію зберігання за KDF свого варіанта
(Argon2id / scrypt / bcrypt / PBKDF2), додає «перець» і перевірку за сталий час.
"""

import base64
import hashlib
import hmac
import os


PEPPER = os.environ.get("AUTH_PEPPER", "").encode()

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32


# ВРАЗЛИВИЙ зразок (для порівняння у звіті) — НЕ використовувати:
def hash_password_insecure(password: str) -> str:
    # ВРАЗЛИВО: швидка хеш-функція без солі — вразлива до райдужних таблиць.
    return hashlib.sha256(password.encode()).hexdigest()


def hash_password(password: str) -> str:
    """БЕЗПЕЧНО: реалізуйте зберігання за KDF свого варіанта.

    Вимоги:
      – унікальна випадкова сіль на кожен пароль (>= 16 байтів);
      – «перець» із секретного сховища (тут — змінна середовища PEPPER);
      – параметри KDF за чинними рекомендаціями (RFC 9106 для Argon2id).
    """
    salt = os.urandom(SALT_BYTES)
    dk = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    params = f"n={SCRYPT_N},r={SCRYPT_R},p={SCRYPT_P}"
    return f"scrypt${params}${_b64(salt)}${_b64(dk)}"


def verify_password(stored: str, password: str) -> bool:
    """Перевірка пароля. Порівняння тегів — лише за сталий час (hmac.compare_digest)."""
    try:
        algo, params, salt_b64, dk_b64 = stored.split("$")
        values = dict(item.split("=") for item in params.split(","))
        n, r, p = int(values["n"]), int(values["r"]), int(values["p"])
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
    except (ValueError, KeyError):
        return False
    if algo != "scrypt":
        return False
    dk = _scrypt(password, salt, n, r, p)
    return hmac.compare_digest(dk, expected)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    data = _peppered(password.encode())
    return hashlib.scrypt(data, salt=salt, n=n, r=r, p=p, dklen=KEY_BYTES)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _peppered(data: bytes) -> bytes:
    return hmac.new(PEPPER, data, hashlib.sha256).digest() if PEPPER else data
