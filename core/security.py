import hmac
import hashlib
import json
import os
import string
from pathlib import Path
from typing import Dict, Tuple

from django.conf import settings


def load_password_policy() -> Dict:
    default_policy = {
        "password_min_length": 10,
        "password_require_uppercase": True,
        "password_require_lowercase": True,
        "password_require_digit": True,
        "password_require_special": True,
        "password_history_limit": 3,
        "login_attempts_limit": 3,
        "dictionary_blacklist": ["password", "qwerty", "admin"],
    }
    path = getattr(settings, "PASSWORD_POLICY_PATH", None)
    if not path:
        return default_policy
    path = Path(path)
    if not path.exists():
        return default_policy
    with path.open("r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            default_policy.update(data)
        except json.JSONDecodeError:
            return default_policy
    return default_policy


def generate_salt() -> str:
    return os.urandom(16).hex()


def hmac_hash_password(salt: str, password: str) -> str:
    key = settings.SECRET_KEY.encode()
    message = (salt + password).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_password(salt: str, password: str, password_hash: str) -> bool:
    return hmac.compare_digest(hmac_hash_password(salt, password), password_hash)


def validate_password(password: str, policy: Dict) -> Tuple[bool, str]:
    min_length = policy.get("password_min_length", 10)
    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters."
    if policy.get("password_require_uppercase", True) and not any(c.isupper() for c in password):
        return False, "Password must include an uppercase letter."
    if policy.get("password_require_lowercase", True) and not any(c.islower() for c in password):
        return False, "Password must include a lowercase letter."
    if policy.get("password_require_digit", True) and not any(c.isdigit() for c in password):
        return False, "Password must include a digit."
    specials = set(string.punctuation)
    if policy.get("password_require_special", True) and not any(c in specials for c in password):
        return False, "Password must include a special character."
    blacklist = policy.get("dictionary_blacklist", [])
    lowered = password.lower()
    if any(b in lowered for b in blacklist):
        return False, "Password is too common."
    return True, ""
