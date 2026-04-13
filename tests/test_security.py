from __future__ import annotations

import time
import unittest

from ids.security import create_jwt, decode_and_verify_jwt


class SecurityTests(unittest.TestCase):
    def test_jwt_roundtrip(self) -> None:
        payload = {
            "sub": "alice",
            "role": "admin",
            "type": "access",
            "exp": int(time.time()) + 60,
        }
        token = create_jwt(payload, "secret")
        decoded = decode_and_verify_jwt(token, "secret")

        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["sub"], "alice")
        self.assertEqual(decoded["role"], "admin")

    def test_jwt_expired_token_rejected(self) -> None:
        payload = {
            "sub": "alice",
            "role": "admin",
            "type": "access",
            "exp": int(time.time()) - 1,
        }
        token = create_jwt(payload, "secret")
        decoded = decode_and_verify_jwt(token, "secret")
        self.assertIsNone(decoded)


if __name__ == "__main__":
    unittest.main()
