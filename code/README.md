# ЛР3. Розроблення підсистеми ідентифікації та автентифікації

Дисципліна "Безпека програмного забезпечення", КПІ ім. Ігоря Сікорського.
Віжуткін Ілля, група ІП-31, варіант 4.

Варіант 4: KDF scrypt, другий фактор HOTP (RFC 4226), блокування за парою
"обліковий запис + IP", трійка Андерсона T = 60 діб, R = 6 спроб/хв, P = 1e-07.

Каркас (auth/anderson.py, функція hash_password_insecure і _peppered у
auth/passwords.py) і common/variants.py взято з репозиторію курсу. Власний код:

- lab03_auth/auth/passwords.py - hash_password і verify_password на scrypt
- lab03_auth/auth/lockout.py - блокування за парою PairLockout
- lab03_auth/auth/hotp.py - HOTP: функція hotp, токен HotpToken, перевірка HotpVerifier
- lab03_auth/auth/service.py - вхід з паролем і кодом HOTP, AuthService
- lab03_auth/demo.py - демонстрація роботи підсистеми
- lab03_auth/tests/test_variant.py - власні тести
- structure.drawio, structure.png - структурна схема

Усі паролі, перець і секрет HOTP у коді тестові.

Запуск (з каталогу code):

    python -m common.variants 4 --lab 3
    cd lab03_auth
    pip install -r requirements.txt
    python -m auth.anderson
    python demo.py
    python -m pytest tests/
