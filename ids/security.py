from __future__ import annotations

import base64
import json
import hmac
import hashlib
import time


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt), password_hash)


def create_jwt(payload: dict[str, object], secret_key: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_part = _b64url_encode(signature)
    return f"{header_part}.{payload_part}.{signature_part}"


def decode_and_verify_jwt(token: str, secret_key: str) -> dict[str, object] | None:
    try:
        header_part, payload_part, signature_part = token.split(".")
    except ValueError:
        return None

    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    expected_signature = hmac.new(
        secret_key.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()
    try:
        provided_signature = _b64url_decode(signature_part)
    except ValueError:
        return None
    if not hmac.compare_digest(expected_signature, provided_signature):
        return None

    try:
        header = json.loads(_b64url_decode(header_part))
        payload = json.loads(_b64url_decode(payload_part))
    except (ValueError, json.JSONDecodeError):
        return None

    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        return None

    exp = payload.get("exp")
    if not isinstance(exp, int):
        return None
    if int(time.time()) >= exp:
        return None
    return payload
