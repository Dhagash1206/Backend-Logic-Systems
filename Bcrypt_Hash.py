"""
bcrypt_utils.py - Production-level bcrypt password hashing utility
Requirements: pip install bcrypt
"""

import bcrypt
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Constants
DEFAULT_ROUNDS = 12          # OWASP recommended minimum
MIN_ROUNDS = 10
MAX_ROUNDS = 14
MAX_PASSWORD_LENGTH = 72     # bcrypt silently truncates at 72 bytes
MIN_PASSWORD_LENGTH = 8


# Exceptions
class PasswordPolicyError(ValueError):
    """password does not meet policy requirements."""

class BcryptError(RuntimeError):
    """ unexpected bcrypt failure."""


#  Validation 
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
    if not (MIN_ROUNDS <= rounds <= MAX_ROUNDS):
        raise ValueError(
            f"Work factor (rounds) must be between {MIN_ROUNDS} and {MAX_ROUNDS}."
        )


# Core Functions
def hash_password(password: str, rounds: int = DEFAULT_ROUNDS) -> str:
    """
    Hash a plaintext password using bcrypt.

    Args:
        password: Plaintext password string.
        rounds:   bcrypt work factor (cost). Default is 12.

    Returns:
        A bcrypt hash string (60 chars, includes salt).

    Raises:
        PasswordPolicyError: If password violates policy.
        BcryptError:         On unexpected hashing failure.
    """
    _validate_password(password)
    _validate_rounds(rounds)

    try:
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        logger.debug("Password hashed successfully (rounds=%d).", rounds)
        return hashed.decode("utf-8")
    except Exception as exc:
        logger.error("bcrypt hashing failed: %s", exc)
        raise BcryptError("Failed to hash password.") from exc


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.

    Args:
        password: Plaintext password to verify.
        hashed:   Stored bcrypt hash string.

    Returns:
        True if the password matches, False otherwise.

    Raises:
        BcryptError: On unexpected verification failure.
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


def needs_rehash(hashed: str, desired_rounds: int = DEFAULT_ROUNDS) -> bool:
    """
    Check if a stored hash was created with fewer rounds than currently desired.
    Use this to upgrade hashes on successful login.

    Args:
        hashed:         Stored bcrypt hash string.
        desired_rounds: Target work factor.

    Returns:
        True if the hash should be rehashed, False otherwise.
    """
    _validate_rounds(desired_rounds)
    try:
        return bcrypt.checkpw.__module__ and bcrypt.rounds(hashed.encode()) < desired_rounds
    except Exception:
        # If rounds cannot be extracted, flag for rehash
        return True


def get_hash_rounds(hashed: str) -> Optional[int]:
    """Extract the work factor from an existing bcrypt hash."""
    try:
        return bcrypt.rounds(hashed.encode("utf-8"))
    except Exception as exc:
        logger.warning("Could not extract rounds from hash: %s", exc)
        return None
 
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    pwd = "Str0ng$ecurePass!"

    print("=== bcrypt Production Demo ===")

    # Hash
    h = hash_password(pwd, rounds=12)
    print(f"Hash     : {h}")
    print(f"Rounds   : {get_hash_rounds(h)}")


  
    print(f"Correct  : {verify_password(pwd, h)}")

    print(f"Wrong    : {verify_password('wrong_password', h)}")

    print(f"Rehash?  : {needs_rehash(h, desired_rounds=13)}")

    try:
        hash_password("short")
    except PasswordPolicyError as e:
        print(f"Policy   : {e}")
