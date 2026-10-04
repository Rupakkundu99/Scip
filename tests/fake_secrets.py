"""Generates FAKE but realistic-looking secrets at runtime.

Why not just write them in the test files? GitHub "push protection" and other scanners
block commits that contain token-shaped strings, even fake ones. Building them from
random characters at runtime keeps the source clean while still exercising the detectors.
Seeded, so results are reproducible.
"""
import random
import string

_ALNUM = string.ascii_letters + string.digits
_B64 = _ALNUM + "+/"
_UPPER_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _r(seed):
    return random.Random(seed)


def _pick(seed, alphabet, n):
    r = _r(seed)
    return "".join(r.choice(alphabet) for _ in range(n))


def aws_access_key_id(seed=1):
    return "AK" + "IA" + _pick(seed, _UPPER_B32, 16)


def aws_secret_key(seed=2):
    return _pick(seed, _B64, 40)


def github_token(seed=3):
    return "gh" + "p_" + _pick(seed, _ALNUM, 36)


def stripe_live_key(seed=4):
    return "sk_" + "live_" + _pick(seed, _ALNUM, 24)


def google_api_key(seed=5):
    return "AI" + "za" + _pick(seed, _ALNUM + "_-", 35)


def slack_token(seed=6):
    return "xo" + "xb-" + _pick(seed, string.digits, 12) + "-" + _pick(seed + 1, _ALNUM, 24)


def anthropic_key(seed=7):
    return "sk-" + "ant-" + _pick(seed, _ALNUM + "_-", 40)


def jwt(seed=8):
    return "ey" + "J" + _pick(seed, _ALNUM, 20) + ".ey" + "J" + _pick(seed + 1, _ALNUM, 30) + "." + _pick(seed + 2, _ALNUM, 40)


def random_token(seed=9, n=40):
    """A random base64-ish string, as found in real secrets."""
    return _pick(seed, _B64, n)


def strong_password(seed=10):
    return _pick(seed, _ALNUM + "!@#$%^&*", 20)


def private_key_pem(seed=11):
    head = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"
    foot = "-----END " + "RSA PRIVATE KEY" + "-----"
    r = _r(seed)
    body = ["".join(r.choice(_B64) for _ in range(64)) for _ in range(12)]
    return "\n".join([head, *body, foot]) + "\n"
