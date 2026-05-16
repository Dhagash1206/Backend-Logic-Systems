"""
Requirements: pip install pyotp qrcode[pil]
"""

import hmac
import logging
import secrets
import time
from dataclasses import dataclass
import pyotp

logger = logging.getLogger(__name__)

OTP_LENGTH = 6
OTP_TTL_SECONDS = 300
TOTP_WINDOW = 1
MAX_ATTEMPTS = 5
LOCKOUT_TTL = 900


class OTPExpiredError(Exception):
    pass


class OTPInvalidError(Exception):
    pass


class OTPLockedError(Exception):
    pass


class OTPAlreadyUsedError(Exception):
    pass


class _InMemoryStore:
    def __init__(self):
        self._data: dict = {}

    def set(self, key: str, value, ttl: int):
        self._data[key] = {"value": value, "expires_at": time.time() + ttl}

    def get(self, key: str):
        entry = self._data.get(key)

        if not entry:
            return None

        if time.time() > entry["expires_at"]:
            del self._data[key]
            return None

        return entry["value"]

    def delete(self, key: str):
        self._data.pop(key, None)

    def incr(self, key: str, ttl: int) -> int:
        entry = self._data.get(key)

        if not entry or time.time() > entry["expires_at"]:
            self._data[key] = {"value": 1, "expires_at": time.time() + ttl}
            return 1

        entry["value"] += 1
        return entry["value"]

    def exists(self, key: str) -> bool:
        return self.get(key) is not None


class RedisStore:
    def __init__(self, client):
        self._r = client

    def set(self, key: str, value, ttl: int):
        self._r.setex(key, ttl, str(value))

    def get(self, key: str):
        val = self._r.get(key)
        return val.decode() if val else None

    def delete(self, key: str):
        self._r.delete(key)

    def incr(self, key: str, ttl: int) -> int:
        pipe = self._r.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl)
        result = pipe.execute()
        return result[0]

    def exists(self, key: str) -> bool:
        return bool(self._r.exists(key))


@dataclass
class OTPRecord:
    code: str
    expires_at: float
    attempts: int = 0


class NumericOTP:
    def __init__(self, store=None, length: int = OTP_LENGTH, ttl: int = OTP_TTL_SECONDS):
        self._store = store or _InMemoryStore()
        self.length = length
        self.ttl = ttl

    def generate(self, identity: str) -> str:
        self._check_lockout(identity)

        code = "".join(str(secrets.randbelow(10)) for _ in range(self.length))

        self._store.set(f"otp:{identity}", code, self.ttl)
        self._store.delete(f"otp:attempts:{identity}")

        logger.info("OTP generated for identity=%s", identity)

        return code

    def verify(self, identity: str, code: str) -> bool:
        self._check_lockout(identity)

        stored = self._store.get(f"otp:{identity}")

        if stored is None:
            raise OTPExpiredError("OTP has expired or was never issued.")

        if not hmac.compare_digest(stored, code.strip()):
            attempts = self._store.incr(f"otp:attempts:{identity}", LOCKOUT_TTL)

            logger.warning(
                "Invalid OTP for identity=%s (attempt %d)",
                identity,
                attempts
            )

            if attempts >= MAX_ATTEMPTS:
                self._store.set(f"otp:locked:{identity}", "1", LOCKOUT_TTL)
                self._store.delete(f"otp:{identity}")

                raise OTPLockedError(
                    f"Too many failed attempts. Locked for {LOCKOUT_TTL // 60} minutes."
                )

            raise OTPInvalidError(
                f"Invalid OTP. {MAX_ATTEMPTS - attempts} attempts remaining."
            )

        self._store.delete(f"otp:{identity}")
        self._store.delete(f"otp:attempts:{identity}")

        logger.info("OTP verified successfully for identity=%s", identity)

        return True
