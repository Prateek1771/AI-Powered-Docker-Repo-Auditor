import base64
import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

KEY_PATH = Path(".dev-keys/private.pem")

KID = "local-dev-key-1"


@lru_cache(maxsize=1)
def _private_key() -> Any:
    if KEY_PATH.exists():
        return serialization.load_pem_private_key(
            KEY_PATH.read_bytes(),
            password=None,
        )

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    KEY_PATH.parent.mkdir(exist_ok=True)

    KEY_PATH.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return key


def _b64(value: int) -> str:
    length = (value.bit_length() + 7) // 8

    raw = value.to_bytes(length, "big")

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwks() -> dict:
    numbers = _private_key().public_key().public_numbers()

    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": KID,
                "use": "sig",
                "alg": "RS256",
                "n": _b64(numbers.n),
                "e": _b64(numbers.e),
            }
        ]
    }


def mint_token(
    tenant_id: str,
    email: str = "dev@example.com",
    audience: str = "local-client-id",
    ttl_minutes: int = 60,
    token_use: str = "id",
) -> str:
    now = datetime.now(UTC)

    pem = _private_key().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        {
            "sub": tenant_id,
            "email": email,
            "aud": audience,
            "token_use": token_use,
            "iat": now,
            "exp": now + timedelta(minutes=ttl_minutes),
            "jti": str(uuid.uuid4()),
        },
        pem.decode(),
        algorithm="RS256",
        headers={"kid": KID},
    )
