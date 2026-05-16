"""
Requirements: pip install bcrypt
"""

import bcrypt
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Constants
DEFAULT_ROUNDS = 12
MIN_ROUNDS = 10
MAX_ROUNDS = 14
MAX_PASSWORD_LENGTH = 72
MIN_PASSWORD_LENGTH = 8


# Exceptions
class PasswordPolicyError(ValueError):
    """Password does not meet policy requirements."""


class BcryptError(RuntimeError):
    """Unexpected bcrypt failure."""


# Validation
def _validate_password(password: str) -> None:
    """Enforce basic password policy before hashing."""
    
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )

    if len(password.encode("utf-8")) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password exceeds bcrypt's {MAX_PASSWORD_LENGTH}-byte limit. "
            "Use pre-hashing (SHA-256) if longer passwords are required."
        )


def _validate_rounds(rounds: int) -> None:
    """Validate bcrypt work factor."""
    
    if not (MIN_ROUNDS <= rounds <= MAX_ROUNDS):
        raise ValueError(
            f"Work factor (rounds) must be between "
            f"{MIN_ROUNDS} and {MAX_ROUNDS}."
        )


# Core Functions
def hash_password(password: str, rounds: int = DEFAULT_ROUNDS) -> str:
    """
    Hash a plaintext password using bcrypt.
    """

    _validate_password(password)
    _validate_rounds(rounds)

    try:
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)

        logger.debug("Password hashed successfully (rounds=%d).", rounds)
        print(f"New password - {hashed}")

        return hashed.decode("utf-8")

    except Exception as exc:
        logger.error("bcrypt hashing failed: %s", exc)

        raise BcryptError("Failed to hash password.") from exc


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.
    """

    if not isinstance(password, str) or not isinstance(hashed, str):
        raise TypeError("Both password and hash must be strings.")

    try:
        match = bcrypt.checkpw(
            password.encode("utf-8"),
            hashed.encode("utf-8")
        )

        logger.debug("Password verification result: %s", match)

        return match

    except Exception as exc:
        logger.error("bcrypt verification failed: %s", exc)

        raise BcryptError("Failed to verify password.") from exc


def get_hash_rounds(hashed: str) -> Optional[int]:
    """
    Extract bcrypt work factor from hash.
    Example:
    $2b$12$... -> 12
    """

    try:
        return int(hashed.split("$")[2])

    except Exception as exc:
        logger.warning("Could not extract rounds from hash: %s", exc)

        return None


def needs_rehash(
    hashed: str,
    desired_rounds: int = DEFAULT_ROUNDS
) -> bool:
    """
    Check if stored hash should be upgraded.
    """

    _validate_rounds(desired_rounds)

    current_rounds = get_hash_rounds(hashed)

    if current_rounds is None:
        return True

    return current_rounds < desired_rounds


# Demo
if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)

    pwd = "SecurePassword!0"

    print("=== bcrypt Production Demo ===")

    # Hash password
    h = hash_password(pwd, rounds=12)

    print(f"Hash     : {h}")
    print(f"Rounds   : {get_hash_rounds(h)}")

    # Correct password
    print(f"Correct  : {verify_password(pwd, h)}")

    # Wrong password
    print(f"Wrong    : {verify_password('wrong_password', h)}")

    # Rehash check
    print(f"Rehash?  : {needs_rehash(h, desired_rounds=13)}")

    # Policy test
    try:
        hash_password("short")

    except PasswordPolicyError as e:
        print(f"Policy   : {e}")
